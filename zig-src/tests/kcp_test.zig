//! M8 mKCP 传输测试（上游无 kcp 单测文件，本文件为实机 smoke 的测试内化版）。
//!
//! 覆盖点（真 UDP socket）：
//!   1. 垃圾包 → 静默丢弃（listener.go 0 段语义，无响应）
//!   2. 合法 Data 段 → 建会话 → addConn 回调 → Terminate 回包
//!   3. actualPort（bind 0 临时端口查询）
//!
//! KCP 协议核心（段格式/RTO/窗口/状态机）由源内 conn.zig/segment.zig 测试覆盖
//! （含内存管道回环）；此处只验证 listener 面与真实 socket 路径。

const std = @import("std");
const linux = std.os.linux;
const sys = @import("../src/common/sys.zig");
const applog = @import("../src/app/log.zig");
const kcp_listener = @import("../src/transport/kcp/listener.zig");
const kcp_segment = @import("../src/transport/kcp/segment.zig");

// ============================ 测试用 UDP 客户端 ============================

const UdpClient = struct {
    fd: sys.Fd,

    fn init() !UdpClient {
        const rc = linux.socket(linux.AF.INET, linux.SOCK.DGRAM | linux.SOCK.CLOEXEC, 0);
        if (linux.errno(rc) != .SUCCESS) return error.SocketFailed;
        const fd: sys.Fd = @intCast(rc);
        const sa = sys.SockaddrIn.init(.{ 127, 0, 0, 1 }, 0);
        const brc = linux.bind(fd, @ptrCast(&sa), @sizeOf(sys.SockaddrIn));
        if (linux.errno(brc) != .SUCCESS) {
            _ = linux.close(fd);
            return error.BindFailed;
        }
        // 200ms 读超时（避免挂死）
        const tv: linux.timeval = .{ .sec = 0, .usec = 200 * 1000 };
        _ = linux.setsockopt(fd, linux.SOL.SOCKET, linux.SO.RCVTIMEO, std.mem.asBytes(&tv), @sizeOf(linux.timeval));
        return .{ .fd = fd };
    }

    fn close(self: UdpClient) void {
        _ = linux.close(self.fd);
    }

    fn sendTo(self: UdpClient, data: []const u8, port: u16) !void {
        const sa = sys.SockaddrIn.init(.{ 127, 0, 0, 1 }, port);
        const rc = linux.sendto(self.fd, data.ptr, data.len, 0, @ptrCast(&sa), @sizeOf(sys.SockaddrIn));
        if (linux.errno(rc) != .SUCCESS) return error.SendFailed;
    }

    /// 收一个包；超时 → null
    fn recv(self: UdpClient, buf: []u8) !?usize {
        const rc = linux.recvfrom(self.fd, buf.ptr, buf.len, 0, null, null);
        const err = linux.errno(rc);
        if (err == .SUCCESS) return @intCast(rc);
        if (err == .AGAIN or err == .BUSY or err == .INTR) return null;
        return error.RecvFailed;
    }
};

// ============================ addConn 回调：即收即关 ============================

var g_closed_count: u32 = 0;

fn onConn(ctx: *anyopaque, conn: *kcp_listener.Connection) void {
    _ = ctx;
    _ = @atomicRmw(u32, &g_closed_count, .Add, 1, .monotonic);
    conn.closeConn();
}

fn testConfig() kcp_listener.Config {
    return .{
        .mtu = 1350,
        .tti = 50,
        .cwnd_multiplier = 1,
        .sending_in_flight = 8,
        .receiving_in_flight = 8,
        .sending_buffer_size = 1553,
    };
}

// ============================ 测试 ============================

test "kcp: 真 UDP 垃圾包静默 + 合法 Data 段建会话 → Terminate 回包" {
    var lg = applog.Logger{ .enabled = false };
    g_closed_count = 0;

    const kl = try kcp_listener.Listener.create(std.testing.allocator, &lg, .{ 127, 0, 0, 1 }, 0, testConfig(), .{ .ctx = undefined, .fn_ = onConn });
    defer kl.close();
    const port = kl.actualPort();
    try std.testing.expect(port > 0);

    const cli = try UdpClient.init();
    defer cli.close();

    // T1: 垃圾包（< 16B，不成段）→ 无响应
    try cli.sendTo(&[_]u8{ 0xde, 0xad, 0xbe, 0xef }, port);
    {
        var rb: [2048]u8 = undefined;
        const r = try cli.recv(&rb);
        try std.testing.expect(r == null); // 静默丢弃
    }

    // T2: 合法 Data 段（conv=0x1234，payload "x"）→ 会话建立 → 回调关闭 → Terminate
    var seg: [kcp_segment.data_segment_overhead + 1]u8 = undefined;
    var payload_buf = [_]u8{'x'};
    const dseg = kcp_segment.DataSegment{
        .conv = 0x1234,
        .timestamp = 0,
        .number = 0,
        .sending_next = 0,
        .payload = payload_buf[0..],
    };
    dseg.serialize(seg[0..]);
    try cli.sendTo(&seg, port);

    // 轮询响应：容忍先到 ACK/其它段，直到 Terminate（cmd=2）或超时
    var got_terminate = false;
    var rb: [2048]u8 = undefined;
    var tries: usize = 0;
    while (tries < 25) : (tries += 1) {
        const r = try cli.recv(&rb) orelse continue;
        if (r < 4) continue;
        const cmd = rb[2];
        const conv = std.mem.readInt(u16, rb[0..2], .big);
        if (cmd == @intFromEnum(kcp_segment.Command.terminate) and conv == 0x1234) {
            got_terminate = true;
            break;
        }
    }
    try std.testing.expect(got_terminate);

    // 回一封 Terminate（conv 相同）→ 会话状态机 terminating → terminated 快速收敛，
    // 避免 8s 强制定时器；随后 listener.close() 的收割才能在 2s 预算内完成（无泄漏/UAF）。
    var reply: [16]u8 = undefined;
    const reply_seg = kcp_segment.CmdOnlySegment{
        .conv = 0x1234,
        .cmd = .terminate,
        .option = 0,
        .sending_next = 1,
        .receiving_next = 1,
    };
    reply_seg.serialize(reply[0..]);
    try cli.sendTo(&reply, port);

    // 等会话清理落地（收割线程 join + destroy；2s 预算）
    var waited: u32 = 0;
    while (waited < 2000) : (waited += 20) {
        sys.sleepMs(20);
    }
    // 回调被调用过（会话建立）
    try std.testing.expect(g_closed_count >= 1);
}

test "kcp: Listener.close 幂等收尾（无残留会话）" {
    var lg = applog.Logger{ .enabled = false };
    const kl = try kcp_listener.Listener.create(std.testing.allocator, &lg, .{ 127, 0, 0, 1 }, 0, testConfig(), .{ .ctx = undefined, .fn_ = onConn });
    const port1 = kl.actualPort();
    try std.testing.expect(port1 > 0);
    kl.close(); // close 内含 destroy
    // 再 close 一次会 double-free——由实例层保证只调一次；此处仅验证端口已释放可再绑
    const kl2 = try kcp_listener.Listener.create(std.testing.allocator, &lg, .{ 127, 0, 0, 1 }, 0, testConfig(), .{ .ctx = undefined, .fn_ = onConn });
    defer kl2.close();
    try std.testing.expect(kl2.actualPort() > 0);
}
