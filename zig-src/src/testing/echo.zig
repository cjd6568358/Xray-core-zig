//! 测试辅助（仅测试代码引用，exe 构建惰性分析不生成）：
//!   - EchoServer：本地 127.0.0.1:0 echo 服务器（逐连接串行回显）
//!   - socketpairClient：AF_UNIX socketpair 伪客户端——a 端包成 Stream 交给被测侧，
//!     b 端留在测试侧（TcpConn 原语对 unix 流 fd 全部可用：recvfrom/sendto/shutdown）

const std = @import("std");
const linux = std.os.linux;
const sys = @import("../common/sys.zig");
const sock = @import("../common/sock.zig");
const stream = @import("../core/stream.zig");

pub const EchoServer = struct {
    listener: sock.TcpListener,
    thread: std.Thread,
    running: std.atomic.Value(bool) = .init(true),
    served: std.atomic.Value(u32) = .init(0), // 成功 accept 的连接数

    pub fn start() !*EchoServer {
        const self = try std.heap.page_allocator.create(EchoServer);
        errdefer std.heap.page_allocator.destroy(self);
        self.* = .{
            .listener = try sock.TcpListener.bind(.{ 127, 0, 0, 1 }, 0, 64),
            .thread = undefined,
        };
        self.thread = std.Thread.spawn(.{ .stack_size = sys.min_thread_stack }, acceptLoop, .{self}) catch |e| {
            self.listener.close();
            return e;
        };
        return self;
    }

    /// 实际绑定端口（bind 0 → 内核分配）
    pub fn port(self: *const EchoServer) u16 {
        return self.listener.actualPort();
    }

    fn acceptLoop(self: *EchoServer) void {
        while (self.running.load(.acquire)) {
            const conn = (self.listener.accept() catch return) orelse continue; // stop() → shutdown → 退出
            _ = self.served.fetchAdd(1, .monotonic);
            echoConn(conn); // 测试场景单连接，串行回显
        }
    }

    fn echoConn(conn: sock.TcpConn) void {
        defer conn.close();
        var b: [4096]u8 = undefined;
        while (true) {
            const n = conn.read(&b) catch return;
            if (n == 0) return;
            conn.writeAll(b[0..n]) catch return;
        }
    }

    pub fn stop(self: *EchoServer) void {
        self.running.store(false, .release);
        _ = linux.shutdown(self.listener.fd, linux.SHUT.RDWR); // 唤醒阻塞 accept
        self.thread.join();
        self.listener.close();
        std.heap.page_allocator.destroy(self);
    }
};

pub const ClientPair = struct {
    test_side: sock.TcpConn,
    ctx: *stream.TcpStreamCtx,
    test_ctx: ?*stream.TcpStreamCtx = null,
    allocator: std.mem.Allocator,

    pub fn deinit(self: *ClientPair) void {
        if (self.test_ctx) |tc| self.allocator.destroy(tc);
        self.ctx.conn.close();
        self.allocator.destroy(self.ctx);
    }

    /// 被测侧半双工对（reader/writer 同一 fd：a 端读上行、写下行动作分属两条拷贝线程）
    pub fn link(self: *ClientPair) stream.Link {
        const s = self.ctx.stream();
        return .{ .reader = s, .writer = s };
    }

    /// 测试侧（对端 fd）Link：写这里 → 被测侧 link().reader 可读；
    /// 被测侧写 link().writer → 这里可读。socketpair 两端不可自环——
    /// 同侧既写又读必须跨端（link()=fds[0]，testLink()=fds[1]）。
    pub fn testLink(self: *ClientPair) stream.Link {
        if (self.test_ctx == null) {
            const tc = self.allocator.create(stream.TcpStreamCtx) catch unreachable;
            tc.* = .{ .conn = self.test_side };
            self.test_ctx = tc;
        }
        const s = self.test_ctx.?.stream();
        return .{ .reader = s, .writer = s };
    }
};

pub fn socketpairClient(allocator: std.mem.Allocator) !ClientPair {
    var fds: [2]linux.fd_t = undefined;
    const rc = linux.socketpair(linux.AF.UNIX, linux.SOCK.STREAM | linux.SOCK.CLOEXEC, 0, &fds);
    if (linux.errno(rc) != .SUCCESS) return error.SocketPairFailed;
    const ctx = try allocator.create(stream.TcpStreamCtx);
    ctx.* = .{ .conn = .{ .fd = fds[0] } };
    return .{ .test_side = .{ .fd = fds[1] }, .ctx = ctx, .allocator = allocator };
}

/// M17：UDP echo 服务器（bind 127.0.0.1:0；每包 recvfrom 后 sendto 回来源）
pub const UdpEchoServer = struct {
    fd: linux.fd_t,
    thread: std.Thread,
    running: std.atomic.Value(bool) = .init(true),

    pub fn start() !*UdpEchoServer {
        const self = try std.heap.page_allocator.create(UdpEchoServer);
        errdefer std.heap.page_allocator.destroy(self);
        // ⚠️ page_allocator.create 只分配、**不跑字段默认值**：running 必须显式初始化。
        // 否则它是垃圾值，若恰好为 0，loop 的 while 立即退出、从不回包——
        // 表现为客户端 send 成功但 recv 超时（M17 排查多时未发现的真因）。
        self.running = std.atomic.Value(bool).init(true);
        const rc = linux.socket(linux.AF.INET, linux.SOCK.DGRAM | linux.SOCK.CLOEXEC, 0);
        if (linux.errno(rc) != .SUCCESS) return error.SocketFailed;
        self.fd = @intCast(rc);
        const sa = sys.SockaddrIn.init(.{ 127, 0, 0, 1 }, 0);
        const brc = linux.bind(self.fd, @ptrCast(&sa), @sizeOf(sys.SockaddrIn));
        if (linux.errno(brc) != .SUCCESS) {
            _ = linux.close(self.fd);
            return error.BindFailed;
        }
        self.thread = std.Thread.spawn(.{ .stack_size = sys.min_thread_stack }, loop, .{self}) catch |e| {
            _ = linux.close(self.fd);
            return e;
        };
        return self;
    }

    pub fn port(self: *const UdpEchoServer) u16 {
        var sa: sys.SockaddrIn = undefined;
        var slen: linux.socklen_t = @sizeOf(sys.SockaddrIn);
        const rc = linux.getsockname(self.fd, @ptrCast(&sa), &slen);
        if (linux.errno(rc) != .SUCCESS) return 0;
        return sa.port();
    }

    fn loop(self: *UdpEchoServer) void {
        var b: [2048]u8 = undefined;
        // UDP 无 shutdown 语义：用 100ms 收超时轮询 running（shutdown 唤不醒 recvfrom）
        var tv = linux.timeval{ .sec = 0, .usec = 100_000 };
        _ = linux.setsockopt(self.fd, linux.SOL.SOCKET, linux.SO.RCVTIMEO, @ptrCast(&tv), @sizeOf(linux.timeval));
        while (self.running.load(.acquire)) {
            var from: sys.SockaddrIn = undefined;
            var flen: linux.socklen_t = @sizeOf(sys.SockaddrIn);
            const n = linux.recvfrom(self.fd, &b, b.len, 0, @ptrCast(&from), &flen);
            if (linux.errno(n) != .SUCCESS) continue; // 超时/中断：回循环查 running
            const len: usize = @intCast(n);
            _ = linux.sendto(self.fd, &b, len, 0, @ptrCast(&from), flen);
        }
    }

    pub fn stop(self: *UdpEchoServer) void {
        self.running.store(false, .release);
        self.thread.join(); // loop 靠 100ms 收超时轮询退出
        _ = linux.close(self.fd);
        std.heap.page_allocator.destroy(self);
    }
};
