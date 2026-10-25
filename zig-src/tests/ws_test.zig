//! M8 WebSocket 传输测试（移植上游 transport/internet/websocket/ws_test.go
//! Test_listenWSAndDial：真 socket 监听 + 客户端拨号 + 帧收发）。
//!
//! 与源内测试的分工：源内（server.zig）用 socketpair 覆盖握手字节级/会话状态机；
//! 本文件走真 TCP：listen → accept → handshake → Binary 帧回环，客户端手工
//! HTTP 升级 + 掩码帧编解码。覆盖 16 位扩展长度、Ping→Pong、Close 握手。

const std = @import("std");
const linux = std.os.linux;
const sys = @import("../src/common/sys.zig");
const sock = @import("../src/common/sock.zig");
const stream_mod = @import("../src/core/stream.zig");
const wssrv = @import("../src/transport/websocket/server.zig");

const a_global = std.testing.allocator;

// ============================ 客户端帧编解码 ============================

/// 客户端帧（带 mask）；opcode 0x2=Binary 0x9=Ping 0x8=Close
fn clientFrame(payload: []const u8, opcode: u4) ![]u8 {
    const mask = [4]u8{ 0x11, 0x22, 0x33, 0x44 };
    var out: std.ArrayList(u8) = .empty;
    const n = payload.len;
    var hdr: [10]u8 = undefined;
    var hl: usize = 0;
    hdr[0] = 0x80 | @as(u8, opcode);
    if (n < 126) {
        hdr[1] = 0x80 | @as(u8, @intCast(n));
        hl = 2;
    } else if (n < 65536) {
        hdr[1] = 0x80 | 126;
        std.mem.writeInt(u16, hdr[2..4], @intCast(n), .big);
        hl = 4;
    } else {
        hdr[1] = 0x80 | 127;
        std.mem.writeInt(u64, hdr[2..10], @intCast(n), .big);
        hl = 10;
    }
    try out.appendSlice(a_global, hdr[0..hl]);
    try out.appendSlice(a_global, &mask);
    var masked: [1024]u8 = undefined;
    for (payload, 0..) |b, i| masked[i] = b ^ mask[i % 4];
    try out.appendSlice(a_global, masked[0..n]);
    return out.toOwnedSlice(a_global);
}

const ServerFrame = struct { opcode: u8, payload: []u8 };

/// 读一帧服务端帧（不带 mask）。EOF → null
fn readServerFrame(conn: sock.TcpConn) !?ServerFrame {
    var hdr: [2]u8 = undefined;
    if (try readFull(conn, hdr[0..]) == 0) return null;
    std.debug.assert((hdr[0] & 0x80) != 0); // FIN=1
    std.debug.assert((hdr[1] & 0x80) == 0); // 服务端不带 mask
    const opcode = hdr[0] & 0x0F;
    var n: u64 = hdr[1] & 0x7F;
    if (n == 126) {
        var e: [2]u8 = undefined;
        _ = try readFull(conn, e[0..]);
        n = std.mem.readInt(u16, &e, .big);
    } else if (n == 127) {
        var e: [8]u8 = undefined;
        _ = try readFull(conn, e[0..]);
        n = std.mem.readInt(u64, &e, .big);
    }
    const pl = try a_global.alloc(u8, @intCast(n));
    if (n > 0) _ = try readFull(conn, pl);
    return ServerFrame{ .opcode = opcode, .payload = pl };
}

fn readFull(conn: sock.TcpConn, out: []u8) !usize {
    var off: usize = 0;
    while (off < out.len) {
        const n = try conn.read(out[off..]);
        if (n == 0) return off;
        off += n;
    }
    return off;
}

// ============================ 服务端 echo ============================

const EchoArgs = struct {
    listener: sock.TcpListener,
};

fn echoMain(args: *EchoArgs) void {
    var arena_state = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    while (true) {
        const conn = (args.listener.accept() catch return) orelse return; // shutdown → 退出
        handleConn(arena, conn) catch {};
    }
}

fn handleConn(arena: std.mem.Allocator, conn: sock.TcpConn) !void {
    const ctx = try arena.create(stream_mod.TcpStreamCtx);
    ctx.* = .{ .conn = conn };
    const st = ctx.stream();
    switch (wssrv.handshake(arena, st, .{ .path = "/ws" })) {
        .ok => |ws| {
            var sess = ws;
            defer sess.stream().close();
            var rb: [4096]u8 = undefined;
            while (true) {
                const n = sess.stream().read(&rb) catch return;
                if (n == 0) return;
                sess.stream().writeAll(rb[0..n]) catch return;
            }
        },
        else => return, // rejected/dropped：错误响应已写或静默；调用方关
    }
}

// ============================ 测试 ============================

/// 客户端握手（返回时已读走 101 响应头）
fn wsDial(port: u16) !sock.TcpConn {
    const conn = try sock.dialTcp(.{ .v4 = sys.SockaddrIn.init(.{ 127, 0, 0, 1 }, port) }, 3000);
    errdefer conn.close();
    conn.setTimeout(3000);
    var req: [512]u8 = undefined;
    const text = try std.fmt.bufPrint(&req,
        "GET /ws HTTP/1.1\r\nHost: 127.0.0.1:{d}\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n" ++
            "Sec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n", .{port});
    try conn.writeAll(text);
    var resp: [256]u8 = undefined;
    var got: usize = 0;
    while (got < 4 or !std.mem.endsWith(u8, resp[0..got], "\r\n\r\n")) {
        if (got >= resp.len) return error.BadResponse;
        const n = try conn.read(resp[got..]);
        if (n == 0) return error.BadResponse;
        got += n;
    }
    try std.testing.expect(std.mem.startsWith(u8, resp[0..got], "HTTP/1.1 101"));
    return conn;
}

test "ws: 真 socket listen+dial+Binary 帧回环（上游 Test_listenWSAndDial）" {
    const listener = try sock.TcpListener.bind(.{ 127, 0, 0, 1 }, 0, 16);
    defer listener.close();
    const port = listener.actualPort();
    var args = EchoArgs{ .listener = listener };
    const th = try std.Thread.spawn(.{ .stack_size = sys.min_thread_stack }, echoMain, .{&args});
    defer {
        _ = linux.shutdown(listener.fd, linux.SHUT.RDWR);
        th.join();
    }

    // ---- 连接 1：200B 载荷（16 位扩展长度帧）----
    {
        const conn = try wsDial(port);
        defer conn.close();
        var payload: [200]u8 = undefined;
        for (&payload, 0..) |*b, i| b.* = @intCast(i % 251);
        const frame = try clientFrame(&payload, 0x2);
        defer a_global.free(frame);
        try conn.writeAll(frame);
        const fr = (try readServerFrame(conn)) orelse return error.NoFrame;
        defer a_global.free(fr.payload);
        try std.testing.expectEqual(@as(u8, 0x2), fr.opcode);
        try std.testing.expectEqualSlices(u8, &payload, fr.payload);
    }

    // ---- 连接 2：短载荷（上游第二条 dial 的重连语义）----
    {
        const conn = try wsDial(port);
        defer conn.close();
        const frame = try clientFrame("Test connection 2", 0x2);
        defer a_global.free(frame);
        try conn.writeAll(frame);
        const fr = (try readServerFrame(conn)) orelse return error.NoFrame;
        defer a_global.free(fr.payload);
        try std.testing.expectEqualStrings("Test connection 2", fr.payload);
    }

    // ---- 连接 3：Ping→Pong + Close 握手 ----
    {
        const conn = try wsDial(port);
        defer conn.close();
        // Ping（payload "ping-m8"）→ 服务端同载荷 Pong
        const ping = try clientFrame("ping-m8", 0x9);
        defer a_global.free(ping);
        try conn.writeAll(ping);
        const pong = (try readServerFrame(conn)) orelse return error.NoFrame;
        defer a_global.free(pong.payload);
        try std.testing.expectEqual(@as(u8, 0xA), pong.opcode);
        try std.testing.expectEqualStrings("ping-m8", pong.payload);

        // Close（code 1000）→ 服务端回显 Close 后 EOF
        var close_pl: [2]u8 = undefined;
        std.mem.writeInt(u16, &close_pl, 1000, .big);
        const close = try clientFrame(&close_pl, 0x8);
        defer a_global.free(close);
        try conn.writeAll(close);
        const cf = (try readServerFrame(conn)) orelse return error.NoFrame;
        defer a_global.free(cf.payload);
        try std.testing.expectEqual(@as(u8, 0x8), cf.opcode);
        const eof = (try readServerFrame(conn)) orelse null;
        try std.testing.expect(eof == null); // 回显 Close 后 TCP EOF
    }
}
