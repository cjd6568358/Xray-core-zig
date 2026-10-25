//! 统一流接口（§3.3）——Go stat.Connection 的 vtable 等价物。
//! 三种传输（TCP裸 / WS / KCP）的会话都实现它。

const std = @import("std");
const sock = @import("../common/sock.zig");

pub const Stream = struct {
    ctx: *anyopaque,
    readFn: *const fn (ctx: *anyopaque, buf: []u8) anyerror!usize, // 返回 0 = EOF
    writeAllFn: *const fn (ctx: *anyopaque, buf: []const u8) anyerror!void,
    closeFn: *const fn (ctx: *anyopaque) void,
    setTimeoutFn: *const fn (ctx: *anyopaque, ms: i64) void,
    shutdownWriteFn: *const fn (ctx: *anyopaque) void,
    /// 可选：一次写出多段（writev）。为 null 时 writeAllVec 退化为逐段 writeAll。
    /// 只有真实 socket（TcpStreamCtx）提供；WS/KCP 包装层按需透传。
    writeVecFn: ?*const fn (ctx: *anyopaque, parts: []const []const u8) anyerror!void = null,

    pub fn read(self: Stream, buf: []u8) anyerror!usize {
        return self.readFn(self.ctx, buf);
    }

    pub fn writeAll(self: Stream, data: []const u8) anyerror!void {
        return self.writeAllFn(self.ctx, data);
    }

    /// 多段写（M22）：有 writev 能力时一次 syscall，否则逐段退化。
    pub fn writeAllVec(self: Stream, parts: []const []const u8) anyerror!void {
        if (self.writeVecFn) |f| return f(self.ctx, parts);
        for (parts) |p| try self.writeAllFn(self.ctx, p);
    }

    pub fn close(self: Stream) void {
        self.closeFn(self.ctx);
    }

    pub fn setTimeout(self: Stream, ms: i64) void {
        self.setTimeoutFn(self.ctx, ms);
    }

    /// 半关闭（TCP: shutdown(SHUT_WR)；对端 read 返 0）。
    /// 对应 Go 侧 output 管道关闭后入站读_EOF 的传播。
    pub fn shutdownWrite(self: Stream) void {
        self.shutdownWriteFn(self.ctx);
    }
};

/// dispatcher 交付给出站的半双工对（对应 Go transport.Link）：
///   reader：客户端→远端（已过协议解码）
///   writer：远端→客户端（将过协议编码）
pub const Link = struct {
    reader: Stream,
    writer: Stream,
};

// ============================ TCP 实现 ============================

pub const TcpStreamCtx = struct {
    conn: sock.TcpConn,

    fn readImpl(ctx: *anyopaque, buf: []u8) anyerror!usize {
        const self: *TcpStreamCtx = @ptrCast(@alignCast(ctx));
        return self.conn.read(buf) catch |e| switch (e) {
            sock.SocketError.WouldBlock => error.Timeout,
            sock.SocketError.ConnReset => error.ConnectionResetByPeer,
            else => error.Unexpected,
        };
    }

    fn writeAllImpl(ctx: *anyopaque, data: []const u8) anyerror!void {
        const self: *TcpStreamCtx = @ptrCast(@alignCast(ctx));
        return self.conn.writeAll(data) catch |e| switch (e) {
            sock.SocketError.WouldBlock => error.Timeout,
            sock.SocketError.ConnReset => error.BrokenPipe,
            else => error.Unexpected,
        };
    }

    fn writeVecImpl(ctx: *anyopaque, parts: []const []const u8) anyerror!void {
        const self: *TcpStreamCtx = @ptrCast(@alignCast(ctx));
        return self.conn.writeAllVec(parts) catch |e| switch (e) {
            sock.SocketError.WouldBlock => error.Timeout,
            sock.SocketError.ConnReset => error.BrokenPipe,
            else => error.Unexpected,
        };
    }

    fn closeImpl(ctx: *anyopaque) void {
        const self: *TcpStreamCtx = @ptrCast(@alignCast(ctx));
        self.conn.close();
    }

    fn setTimeoutImpl(ctx: *anyopaque, ms: i64) void {
        const self: *TcpStreamCtx = @ptrCast(@alignCast(ctx));
        self.conn.setTimeout(ms);
    }

    fn shutdownWriteImpl(ctx: *anyopaque) void {
        const self: *TcpStreamCtx = @ptrCast(@alignCast(ctx));
        self.conn.shutdownWrite();
    }

    pub fn stream(self: *TcpStreamCtx) Stream {
        return .{
            .ctx = self,
            .readFn = readImpl,
            .writeAllFn = writeAllImpl,
            .closeFn = closeImpl,
            .setTimeoutFn = setTimeoutImpl,
            .shutdownWriteFn = shutdownWriteImpl,
            .writeVecFn = writeVecImpl,
        };
    }
};

test "stream interface via socketpair-like flow (in-memory)" {
    // 用内存伪流验证 vtable 调度
    const MemCtx = struct {
        data: [16]u8 = undefined,
        len: usize = 0,
        pos: usize = 0,

        fn readImpl(ctx: *anyopaque, buf: []u8) anyerror!usize {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            if (self.pos >= self.len) return 0;
            const n = @min(buf.len, self.len - self.pos);
            @memcpy(buf[0..n], self.data[self.pos..][0..n]);
            self.pos += n;
            return n;
        }
        fn writeAllImpl(ctx: *anyopaque, data: []const u8) anyerror!void {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            @memcpy(self.data[self.len..][0..data.len], data);
            self.len += data.len;
        }
        fn closeImpl(_: *anyopaque) void {}
        fn setTimeoutImpl(_: *anyopaque, _: i64) void {}
        fn shutdownWriteImpl(_: *anyopaque) void {}
    };
    var src = MemCtx{};
    src.data[0..5].* = .{ 'h', 'e', 'l', 'l', 'o' };
    src.len = 5;
    var dst = MemCtx{};
    const src_stream = Stream{ .ctx = &src, .readFn = MemCtx.readImpl, .writeAllFn = MemCtx.writeAllImpl, .closeFn = MemCtx.closeImpl, .setTimeoutFn = MemCtx.setTimeoutImpl, .shutdownWriteFn = MemCtx.shutdownWriteImpl };
    const dst_stream = Stream{ .ctx = &dst, .readFn = MemCtx.readImpl, .writeAllFn = MemCtx.writeAllImpl, .closeFn = MemCtx.closeImpl, .setTimeoutFn = MemCtx.setTimeoutImpl, .shutdownWriteFn = MemCtx.shutdownWriteImpl };
    var buf: [16]u8 = undefined;
    const n = try src_stream.read(buf[0..]);
    try dst_stream.writeAll(buf[0..n]);
    try std.testing.expectEqualStrings("hello", dst.data[0..dst.len]);
    // 半关闭接口可达
    dst_stream.shutdownWrite();
}
