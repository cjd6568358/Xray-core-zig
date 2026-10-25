//! 流量统计（对照 features/stats + app/dispatcher WrapLink + app/proxyman/inbound getStatCounter）
//!
//! channel 命名与开关语义严格对齐上游：
//!   * `inbound>>>TAG>>>traffic>>>uplink|downlink`（system 级开关）
//!   * `user>>>EMAIL>>>traffic>>>uplink|downlink`（user 级开关，按 level 取 policy）
//! 计数方向：Reader 计 uplink（客户端→服务端），Writer 计 downlink（服务端→客户端）。
//!
//! 与上游的差异（已登记）：上游经 gRPC StatsService 查询；本实现无 API，
//! 由 selfcheck 每 60s 打一行输出。计数器/开关/channel 名不受影响。

const std = @import("std");
const sys = @import("../common/sys.zig");

/// 单个 channel 的计数器（上游 stats.Counter 的原子实现）
pub const Counter = struct {
    value: std.atomic.Value(u64) = .init(0),

    pub fn add(self: *Counter, n: u64) void {
        _ = self.value.fetchAdd(n, .monotonic);
    }

    pub fn get(self: *const Counter) u64 {
        return self.value.load(.monotonic);
    }

    pub fn set(self: *Counter, v: u64) void {
        self.value.store(v, .monotonic);
    }
};

/// channel 名 → 计数器（上游 Manager.GetOrRegisterCounter）
pub const Manager = struct {
    alloc: std.mem.Allocator,
    mu: sys.Mutex = .{},
    map: std.StringHashMapUnmanaged(*Counter) = .empty,

    pub fn init(alloc: std.mem.Allocator) Manager {
        return .{ .alloc = alloc };
    }

    pub fn deinit(self: *Manager) void {
        var it = self.map.iterator();
        while (it.next()) |e| {
            self.alloc.free(e.key_ptr.*);
            self.alloc.destroy(e.value_ptr.*);
        }
        self.map.deinit(self.alloc);
    }

    /// 上游 GetOrRegisterCounter：name 由调用方按上游格式拼好
    pub fn getOrRegisterCounter(self: *Manager, name: []const u8) ?*Counter {
        self.mu.lock();
        defer self.mu.unlock();
        if (self.map.get(name)) |c| return c;
        const c = self.alloc.create(Counter) catch return null;
        c.* = .{};
        const key = self.alloc.dupe(u8, name) catch {
            self.alloc.destroy(c);
            return null;
        };
        self.map.put(self.alloc, key, c) catch {
            self.alloc.free(key);
            self.alloc.destroy(c);
            return null;
        };
        return c;
    }

    /// 供 selfcheck 输出：按注册顺序快照（name,value）列表
    pub fn snapshot(self: *Manager, alloc: std.mem.Allocator) ![]Entry {
        self.mu.lock();
        defer self.mu.unlock();
        var out = try alloc.alloc(Entry, self.map.count());
        var it = self.map.iterator();
        var i: usize = 0;
        while (it.next()) |e| {
            out[i] = .{ .name = e.key_ptr.*, .value = e.value_ptr.*.get() };
            i += 1;
        }
        return out;
    }

    pub const Entry = struct {
        name: []const u8,
        value: u64,
    };
};

/// 一次连接涉及的 4 个计数器槽（上游 WrapLink：Reader 计 uplink、Writer 计 downlink，
/// 按 inbound tag 与 user email 两个维度各一对）
pub const Counters = struct {
    inbound_up: ?*Counter = null,
    inbound_down: ?*Counter = null,
    user_up: ?*Counter = null,
    user_down: ?*Counter = null,

    pub fn any(self: Counters) bool {
        return self.inbound_up != null or self.inbound_down != null or
            self.user_up != null or self.user_down != null;
    }
};

// ============================ channel 名构造 ============================

pub const INBOUND_UP_TMPL = "inbound>>>{s}>>>traffic>>>uplink";
pub const INBOUND_DOWN_TMPL = "inbound>>>{s}>>>traffic>>>downlink";
pub const USER_UP_TMPL = "user>>>{s}>>>traffic>>>uplink";
pub const USER_DOWN_TMPL = "user>>>{s}>>>traffic>>>downlink";

/// 拼 inbound uplink channel 名（写入 out，返回长度）
pub fn inboundUpName(out: []u8, tag: []const u8) []const u8 {
    return std.fmt.bufPrint(out, INBOUND_UP_TMPL, .{tag}) catch return out[0..0];
}

pub fn inboundDownName(out: []u8, tag: []const u8) []const u8 {
    return std.fmt.bufPrint(out, INBOUND_DOWN_TMPL, .{tag}) catch return out[0..0];
}

pub fn userUpName(out: []u8, email: []const u8) []const u8 {
    return std.fmt.bufPrint(out, USER_UP_TMPL, .{email}) catch return out[0..0];
}

pub fn userDownName(out: []u8, email: []const u8) []const u8 {
    return std.fmt.bufPrint(out, USER_DOWN_TMPL, .{email}) catch return out[0..0];
}

// ============================ 测试 ============================

test "stats: channel 名格式与上游一致" {
    var b: [128]u8 = undefined;
    try std.testing.expectEqualStrings("inbound>>>inbound-19001>>>traffic>>>uplink", inboundUpName(&b, "inbound-19001"));
    try std.testing.expectEqualStrings("inbound>>>inbound-19001>>>traffic>>>downlink", inboundDownName(&b, "inbound-19001"));
    try std.testing.expectEqualStrings("user>>>pb8lpgli>>>traffic>>>uplink", userUpName(&b, "pb8lpgli"));
    try std.testing.expectEqualStrings("user>>>pb8lpgli>>>traffic>>>downlink", userDownName(&b, "pb8lpgli"));
}

test "stats: GetOrRegister 幂等 + 计数累加" {
    var mgr = Manager.init(std.testing.allocator);
    defer mgr.deinit();
    const c1 = mgr.getOrRegisterCounter("inbound>>>t>>>traffic>>>uplink").?;
    const c2 = mgr.getOrRegisterCounter("inbound>>>t>>>traffic>>>uplink").?;
    try std.testing.expectEqual(c1, c2); // 同名返回同一计数器
    c1.add(100);
    c1.add(23);
    try std.testing.expectEqual(@as(u64, 123), c2.get());

    const d = mgr.getOrRegisterCounter("user>>>a>>>traffic>>>downlink").?;
    d.add(7);
    try std.testing.expectEqual(@as(u64, 7), d.get());
    try std.testing.expectEqual(@as(u64, 123), c1.get());
}

test "stats: snapshot 覆盖全部 channel" {
    var mgr = Manager.init(std.testing.allocator);
    defer mgr.deinit();
    _ = mgr.getOrRegisterCounter("inbound>>>a>>>traffic>>>uplink").?;
    _ = mgr.getOrRegisterCounter("user>>>b>>>traffic>>>downlink").?;
    const snap = try mgr.snapshot(std.testing.allocator);
    defer std.testing.allocator.free(snap);
    try std.testing.expectEqual(@as(usize, 2), snap.len);
}
