//! 8KB 定长缓冲池（对应 Go buf.Size=8192；§3.5 数据面缓冲策略）。
//! 互斥保护的空闲链表，拷贝循环取用后归还。

const std = @import("std");
const sys = @import("sys.zig");
const trace_mod = @import("../app/trace.zig");

pub const buffer_size = 8192;
pub const max_buffers = 256; // 上限 2MB 池

pub const Buffer = struct {
    data: [buffer_size]u8 = undefined,
};

pub const Pool = struct {
    mu: sys.Mutex = .{},
    free: std.ArrayList(*Buffer) = .empty,
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) Pool {
        return .{ .allocator = allocator };
    }

    pub fn deinit(self: *Pool) void {
        self.mu.lock();
        defer self.mu.unlock();
        for (self.free.items) |b| self.allocator.destroy(b);
        self.free.deinit(self.allocator);
        self.free = .empty;
    }

    pub fn get(self: *Pool) *Buffer {
        self.mu.lock();
        if (self.free.items.len > 0) {
            const b = self.free.pop().?;
            self.mu.unlock();
            return b;
        }
        self.mu.unlock();
        const b = self.allocator.create(Buffer) catch @panic("oom: buffer pool");
        return b;
    }

    pub fn put(self: *Pool, b: *Buffer) void {
        self.mu.lock();
        defer self.mu.unlock();
        if (self.free.items.len >= max_buffers) {
            self.mu.unlock();
            self.allocator.destroy(b);
            self.mu.lock();
            return;
        }
        self.free.append(self.allocator, b) catch {
            self.mu.unlock();
            self.allocator.destroy(b);
            self.mu.lock();
        };
    }
};

// ============================ Session（§5.4 连接级上下文） ============================

pub const Session = struct {
    inbound_tag: []const u8 = "",
    inbound_protocol: []const u8 = "", // vless/vmess——freedom 内置默认规则判定依据（§5.6）
    source: [64]u8 = undefined,
    source_len: usize = 0,
    user_email: []const u8 = "",
    dest: [72]u8 = undefined,
    dest_len: usize = 0,
    /// 连接生命周期打点（app/trace.zig）。由入站协议处理器在建立 Session 时挂上，
    /// dispatcher/freedom/mux 沿途共用同一条 Trace；null = 不打点（单测默认）。
    trace: ?*trace_mod.Trace = null,

    pub fn setSource(self: *Session, s: []const u8) void {
        const n = @min(s.len, self.source.len);
        @memcpy(self.source[0..n], s[0..n]);
        self.source_len = n;
    }

    pub fn getSource(self: *const Session) []const u8 {
        return self.source[0..self.source_len];
    }

    pub fn setDest(self: *Session, s: []const u8) void {
        const n = @min(s.len, self.dest.len);
        @memcpy(self.dest[0..n], s[0..n]);
        self.dest_len = n;
    }

    pub fn getDest(self: *const Session) []const u8 {
        return self.dest[0..self.dest_len];
    }
};

// ============================ Policy（表 4-1 固定默认值） ============================

pub const Policy = struct {
    pub const handshake_timeout_ms: i64 = 60 * 1000; // Handshake 60s
    pub const connection_idle_ms: i64 = 300 * 1000; // ConnectionIdle 300s
    pub const uplink_only_ms: i64 = 1 * 1000; // UplinkOnly 1s
    pub const downlink_only_ms: i64 = 1 * 1000; // DownlinkOnly 1s
    /// §3.5 并发上限：超限新连接直接关闭并记 overload 日志（可调）
    /// 入站并发连接上限。**0 = 不限**；此处取 256 作为设备资源安全阀
    /// （512MB RAM / A53：256×3 线程 ≈ 768 仍在可承受范围）。
    /// 上游对入站 TCP 无硬上限（MaxConnection 仅用于 mux 客户端策略），
    /// 故属已登记的"自定策略"偏差。M12 实机：曾设 64 → 地铁弱网重连风暴被拒 7244 次。
    pub const max_concurrent_conns: u32 = 256;
    /// §7.4 自检日志周期
    pub const selfcheck_interval_ms: u32 = 60 * 1000;
};

test "pool get/put/get" {
    var p = Pool.init(std.testing.allocator);
    defer p.deinit();
    const b1 = p.get();
    b1.data[0] = 0xAA;
    p.put(b1);
    const b2 = p.get();
    try std.testing.expectEqual(@as(u8, 0xAA), b2.data[0]); // 复用同一块
    p.put(b2);
}

test "session set/get" {
    var s = Session{};
    s.setSource("1.2.3.4:5678");
    try std.testing.expectEqualStrings("1.2.3.4:5678", s.getSource());
    s.setDest("example.com:443");
    try std.testing.expectEqualStrings("example.com:443", s.getDest());
}
