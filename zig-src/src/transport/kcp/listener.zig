//! mKCP 监听（§5.10；对照 transport/internet/kcp/listener.go + udp.Hub 服务端子集
//! @ v26.10.21）。
//!
//! UDP 收包线程：recvfrom → KCPPacketReader 整包切段 → 0 段丢弃并记日志
//! （listener.go:75-77 原样：仅整包 0 段才丢）→ 按 (源 IPv4, 源端口, conv) 会话
//! 分发；新会话：cmd==Terminate 直接忽略，否则建 Connection（Output = 定向
//! sendto + retry.Timed(5,100)；Closer = 表移除 + 入收割队列）→ addConn 回调
//! （M6 阶段为「VMess pending M7」占位：记日志 + 优雅关闭）。
//! 收割：recv 空闲路径 + close 时扫描 dying，thread_done && cleanup_done 的
//! 会话 join + destroy（对应 Go GC）。

const std = @import("std");
const linux = std.os.linux;
const sys = @import("../../common/sys.zig");
const sock = @import("../../common/sock.zig");
const applog = @import("../../app/log.zig");
const segment = @import("segment.zig");
const conn_pkg = @import("conn.zig");


pub const Connection = conn_pkg.Connection;
pub const Config = conn_pkg.Config;

/// 会话键：(源 IPv4, 源端口, conv) 打包为 u64
pub fn sessionKey(ip: [4]u8, port: u16, conv: u16) u64 {
    const ip_be = std.mem.readInt(u32, &ip, .big);
    return (@as(u64, ip_be) << 32) | (@as(u64, port) << 16) | conv;
}

pub const AddConn = struct {
    ctx: *anyopaque,
    /// 新会话建立（首个非 Terminate 包）。M6 占位实现：记日志 + closeConn；
    /// M7：VMess 接管（spawn 协议线程消费 conn.stream()）。
    fn_: *const fn (ctx: *anyopaque, conn: *Connection) void,

    pub fn run(self: AddConn, conn: *Connection) void {
        self.fn_(self.ctx, conn);
    }
};

const SessionEntry = struct {
    key: u64,
    conn: *Connection,
    out: *OutCtx,
};

/// 会话定向输出（listener.go Writer）：序列化 + sendto + retry.Timed(5,100)
const OutCtx = struct {
    listener: *Listener,
    addr: sys.SockaddrIn,
    key: u64,
    conn: ?*Connection = null, // create 后回填

    fn write(ctx: *anyopaque, seg: segment.Segment) anyerror!void {
        const self: *OutCtx = @ptrCast(@alignCast(ctx));
        if (self.listener.fd < 0) return error.Closed;
        var buf: [1400]u8 = undefined;
        const n = seg.byteSize();
        if (n > buf.len) return error.MessageTooBig;
        seg.serialize(buf[0..n]);

        var attempt: u32 = 0;
        while (true) {
            const w = linux.sendto(self.listener.fd, buf[0..n].ptr, n, 0, @ptrCast(&self.addr), @sizeOf(sys.SockaddrIn));
            if (linux.errno(w) == .SUCCESS) return;
            attempt += 1;
            if (attempt >= 5) return error.SendFailed; // Timed(5, 100)
            sys.sleepMs(100);
        }
    }

    /// listener.go Writer.Close：会话终结 → 表移除 + 入收割队列
    fn close(ctx: *anyopaque) void {
        const self: *OutCtx = @ptrCast(@alignCast(ctx));
        const conn = self.conn orelse return;
        self.listener.removeSession(self.key, conn);
    }
};

pub const Listener = struct {
    alloc: std.mem.Allocator,
    logger: *applog.Logger,
    fd: sys.Fd = 0,
    port: u16,
    config: Config,
    add_conn: AddConn,

    mu: sys.Mutex = .{},
    sessions: std.HashMapUnmanaged(u64, *SessionEntry, std.hash_map.AutoContext(u64), 80) = .empty,
    dying: std.ArrayList(*SessionEntry) = .empty,

    running: std.atomic.Value(bool) = .init(true),
    recv_thread: ?std.Thread = null,
    recv_buf: []u8 = &.{},

    pub fn create(
        alloc: std.mem.Allocator,
        logger: *applog.Logger,
        listen: [4]u8,
        port: u16,
        config: Config,
        add_conn: AddConn,
    ) !*Listener {
        const rc = linux.socket(linux.AF.INET, linux.SOCK.DGRAM | linux.SOCK.CLOEXEC, 0);
        if (linux.errno(rc) != .SUCCESS) return error.SocketFailed;
        const fd: sys.Fd = @intCast(rc);
        // 收包空闲轮询节奏（同时驱动收割）
        const tv: linux.timeval = .{ .sec = 0, .usec = 200 * 1000 };
        _ = linux.setsockopt(fd, linux.SOL.SOCKET, linux.SO.RCVTIMEO, std.mem.asBytes(&tv), @sizeOf(linux.timeval));

        const sa = sys.SockaddrIn.init(listen, port);
        const brc = linux.bind(fd, @ptrCast(&sa), @sizeOf(sys.SockaddrIn));
        if (linux.errno(brc) != .SUCCESS) {
            _ = linux.close(fd);
            return error.BindFailed;
        }

        const self = try alloc.create(Listener);
        self.* = .{
            .alloc = alloc,
            .logger = logger,
            .fd = fd,
            .port = port,
            .config = config,
            .add_conn = add_conn,
        };
        self.recv_buf = alloc.alloc(u8, 65536) catch {
            _ = linux.close(fd);
            alloc.destroy(self);
            return error.OutOfMemory;
        };
        // recv 线程走 crypto 栈：onReceive→readPacket 链在 Debug 下帧深实测超 64KB
        // （Segment 联合体含 512B AckSegment 值传递；ReleaseSafe 不崩、Debug 崩）
        self.recv_thread = std.Thread.spawn(.{ .stack_size = sys.crypto_thread_stack }, recvLoop, .{self}) catch {
            alloc.free(self.recv_buf);
            _ = linux.close(fd);
            alloc.destroy(self);
            return error.ThreadSpawnFailed;
        };
        return self;
    }

    /// 实际绑定端口（bind 0 → 内核分配）；测试/实例查询用
    pub fn actualPort(self: *Listener) u16 {
        var sa: sys.SockaddrIn = undefined;
        var len: linux.socklen_t = @sizeOf(sys.SockaddrIn);
        const rc = linux.getsockname(self.fd, @ptrCast(&sa), &len);
        if (linux.errno(rc) != .SUCCESS) return 0;
        return sa.port();
    }

    /// 停收包 + 强制终结存量会话（不销毁容器）。与 deinit 分两步，
    /// 供 Instance.stop 在协议线程收敛前先切断会话（M9：原 close 单步实现会在
    /// 会话线程仍持有 conn 时销毁 listener → 停机 SIGSEGV）。
    pub fn shutdown(self: *Listener) void {
        self.running.store(false, .release);
        _ = linux.shutdown(self.fd, linux.SHUT.RDWR);
        if (self.recv_thread) |t| t.join();
        _ = linux.close(self.fd);
        self.fd = -1; // OutCtx.write 见到负 fd 直接失败，避免误写复用的 fd 号
        if (self.recv_buf.len > 0) self.alloc.free(self.recv_buf);
        self.recv_buf = &.{};

        self.mu.lock();
        var it = self.sessions.valueIterator();
        while (it.next()) |entry| {
            self.dying.append(self.alloc, entry.*) catch {};
        }
        self.sessions.clearRetainingCapacity();
        self.mu.unlock();

        // 强制终结（跳过 8s Terminate 握手；进程即将退出）
        self.mu.lock();
        const snapshot = self.alloc.dupe(*SessionEntry, self.dying.items) catch &.{};
        self.mu.unlock();
        for (snapshot) |entry| entry.conn.forceTerminate();
        if (snapshot.len > 0) self.alloc.free(snapshot);
    }

    /// 收割残留会话 + 释放容器与监听器本体（须在 shutdown 之后、协议线程收敛之后）
    pub fn deinit(self: *Listener) void {
        self.reap(5000);
        self.mu.lock();
        const remaining = self.dying.items.len;
        self.mu.unlock();
        if (remaining > 0) {
            // 会话线程仍未退出：宁可泄漏也不释放内存（释放必然 use-after-free）
            return;
        }
        self.sessions.deinit(self.alloc);
        self.dying.deinit(self.alloc);
        self.alloc.destroy(self);
    }

    /// listener.go Close：shutdown + deinit（测试与单步调用方用）
    pub fn close(self: *Listener) void {
        self.shutdown();
        self.deinit();
    }

    fn reapEntry(self: *Listener, entry: *SessionEntry) void {
        if (entry.conn.reap()) {
            self.alloc.destroy(entry.out);
            self.alloc.destroy(entry);
        }
    }

    /// 收割 dying；budget_ms 内等待未完成者
    fn reap(self: *Listener, budget_ms: u32) void {
        var waited: u32 = 0;
        while (true) {
            var progress = false;
            self.mu.lock();
            var i: usize = 0;
            var ready: [64]*SessionEntry = undefined;
            var count: usize = 0;
            while (i < self.dying.items.len and count < ready.len) {
                const entry = self.dying.items[i];
                if (entry.conn.thread_done.load(.acquire) and entry.conn.cleanup_done.load(.acquire)) {
                    _ = self.dying.orderedRemove(i);
                    ready[count] = entry;
                    count += 1;
                } else {
                    i += 1;
                }
            }
            self.mu.unlock();
            if (count > 0) {
                for (ready[0..count]) |entry| {
                    self.reapEntry(entry);
                }
                progress = true;
            }
            self.mu.lock();
            const remaining = self.dying.items.len;
            self.mu.unlock();
            if (remaining == 0) return;
            if (!progress) {
                if (waited >= budget_ms) return;
                sys.sleepMs(10);
                waited += 10;
            }
        }
    }

    fn reapOnce(self: *Listener) void {
        self.mu.lock();
        var i: usize = 0;
        var ready: [64]*SessionEntry = undefined;
        var count: usize = 0;
        while (i < self.dying.items.len and count < ready.len) {
            const entry = self.dying.items[i];
            if (entry.conn.thread_done.load(.acquire) and entry.conn.cleanup_done.load(.acquire)) {
                _ = self.dying.orderedRemove(i);
                ready[count] = entry;
                count += 1;
            } else {
                i += 1;
            }
        }
        self.mu.unlock();
        for (ready[0..count]) |entry| {
            self.reapEntry(entry);
        }
    }

    fn recvLoop(self: *Listener) void {
        const buf = self.recv_buf;
        while (self.running.load(.acquire)) {
            var sa: sys.SockaddrIn = undefined;
            var slen: linux.socklen_t = @sizeOf(sys.SockaddrIn);
            const n = linux.recvfrom(self.fd, buf.ptr, buf.len, 0, @ptrCast(&sa), &slen);
            switch (linux.errno(n)) {
                .SUCCESS => {},
                .AGAIN, .TIMEDOUT => {
                    self.reapOnce();
                    continue;
                },
                .INTR => continue,
                else => {
                    if (!self.running.load(.acquire)) break;
                    self.reapOnce();
                    continue;
                },
            }
            if (n == 0) continue;
            self.onReceive(buf[0..n], sa);
            self.reapOnce();
        }
    }

    fn onReceive(self: *Listener, data: []const u8, sa: sys.SockaddrIn) void {
        var segs: std.ArrayList(segment.Segment) = .empty;
        defer {
            for (segs.items) |s| s.deinit(self.alloc);
            segs.deinit(self.alloc);
        }
        segment.readPacket(self.alloc, data, &segs) catch {};

        if (segs.items.len == 0) {
            // listener.go:75-77：整包 0 段才丢弃并记日志
            var sb: [96]u8 = undefined;
            const sn = sock.formatV4(sa, &sb);
            var mb: [160]u8 = undefined;
            if (std.fmt.bufPrint(&mb, "discarding invalid payload from {s}", .{sb[0..sn]})) |m| {
                self.logger.info(m);
            } else |_| {}
            return;
        }

        const conv = segs.items[0].conversation();
        const cmd = segs.items[0].command();
        const key = sessionKey(sa.addr, sa.port(), conv);

        self.mu.lock();
        defer self.mu.unlock();

        var conn: *Connection = undefined;
        if (self.sessions.get(key)) |entry| {
            conn = entry.conn;
        } else {
            if (cmd == .terminate) return; // 未知会话的终止包：忽略
            const wctx = self.alloc.create(OutCtx) catch return;
            wctx.* = .{ .listener = self, .addr = sa, .key = key };
            const created = Connection.create(
                self.alloc,
                conv,
                self.config,
                .{ .ctx = wctx, .writeFn = OutCtx.write },
                .{ .ctx = wctx, .closeFn = OutCtx.close },
            ) catch {
                self.alloc.destroy(wctx);
                return;
            };
            wctx.conn = created;
            created.peer = sa; // access 日志的 from 段（此前实例层只能记 "kcp-session"）
            conn = created;
            self.sessions.put(self.alloc, key, self.alloc.create(SessionEntry) catch {
                self.alloc.destroy(created);
                self.alloc.destroy(wctx);
                return;
            }) catch {
                // 表满（1024 容量约束由上游 udp.Hub 承担；此处极端路径直接终止会话）
                created.closeConn();
                return;
            };
            self.sessions.get(key).?.* = .{ .key = key, .conn = created, .out = wctx };
            self.add_conn.run(created); // M6 占位；M7：VMess 接管
        }
        conn.input(segs.items);
    }

    /// listener.go Remove：closer 回调（Terminate 清理线程内执行）
    fn removeSession(self: *Listener, key: u64, conn: *Connection) void {
        self.mu.lock();
        defer self.mu.unlock();
        if (self.sessions.get(key)) |entry| {
            if (entry.conn == conn) {
                _ = self.sessions.remove(key);
                self.dying.append(self.alloc, entry) catch {};
            }
        }
    }
};
