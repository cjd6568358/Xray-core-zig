//! UDP length-prefixed 包读写（对照 common/protocol/packet.go LengthPacketReader
//! + MultiLengthPacketWriter + proxy/vless/encoding/addons.go）
//!
//! 格式：`[2B 大端长度][包数据]`，一个流上可连续多个包。
//! 上游：UDP command 的 VLESS/VMess 载荷即此形态；服务端读包 → 出站 send，
//! 出站 recv → 写回流。

const std = @import("std");
const sys = @import("../common/sys.zig");

pub const MAX_PACKET: usize = 2048; // 上游 UDP 包常规上限（DNS/QUIC 初始包远小于此）

pub const PacketError = error{
    TruncatedLength,
    PacketTooBig,
    ReadFailed,
    StreamClosed,
    OutOfMemory,
};

/// 从流读恰好 n 字节
fn readFull(s: anytype, out: []u8) PacketError!void {
    var off: usize = 0;
    while (off < out.len) {
        const n = s.read(out[off..]) catch return PacketError.ReadFailed;
        if (n == 0) return PacketError.StreamClosed;
        off += n;
    }
}

/// 读一个 length-prefixed 包到 out（返回包长）。上游 LengthPacketReader.ReadMultiBuffer
pub fn readPacket(s: anytype, out: []u8) PacketError!usize {
    var lb: [2]u8 = undefined;
    readFull(s, lb[0..]) catch |e| return e;
    const len = std.mem.readInt(u16, lb[0..2], .big);
    if (len == 0) return 0; // 0 长度包：保留（上游照样交付）
    if (len > out.len) return PacketError.PacketTooBig;
    try readFull(s, out[0..len]);
    return len;
}

/// 写一个 length-prefixed 包。上游 MultiLengthPacketWriter.WriteMultiBuffer
pub fn writePacket(s: anytype, data: []const u8) PacketError!void {
    if (data.len > MAX_PACKET) return PacketError.PacketTooBig;
    var lb: [2]u8 = undefined;
    std.mem.writeInt(u16, lb[0..2], @intCast(data.len), .big);
    s.writeAll(lb[0..]) catch return PacketError.ReadFailed;
    s.writeAll(data) catch return PacketError.ReadFailed;
}

// ============================ 测试 ============================

const MemStream = struct {
    data: []const u8,
    off: usize = 0,

    fn read(self: *MemStream, out: []u8) !usize {
        if (self.off >= self.data.len) return 0;
        const n = @min(out.len, self.data.len - self.off);
        @memcpy(out[0..n], self.data[self.off..][0..n]);
        self.off += n;
        return n;
    }

    fn writeAll(self: *MemStream, in: []const u8) !void {
        _ = self;
        _ = in;
        return error.NotImplemented;
    }
};

test "udp packet: 单包 roundtrip（2B 大端长度前缀）" {
    const payload = "hello-udp-packet";
    var buf: [2 + MAX_PACKET]u8 = undefined;
    std.mem.writeInt(u16, buf[0..2], @intCast(payload.len), .big);
    @memcpy(buf[2..][0..payload.len], payload);
    var ms = MemStream{ .data = buf[0 .. 2 + payload.len] };
    var out: [MAX_PACKET]u8 = undefined;
    const n = try readPacket(&ms, &out);
    try std.testing.expectEqualStrings(payload, out[0..n]);
}

test "udp packet: 连续多包依次读出" {
    var buf: [64]u8 = undefined;
    var w: usize = 0;
    for ([_][]const u8{ "aaa", "bbbb", "c" }) |p| {
        std.mem.writeInt(u16, buf[w..][0..2], @intCast(p.len), .big);
        w += 2;
        @memcpy(buf[w..][0..p.len], p);
        w += p.len;
    }
    var ms = MemStream{ .data = buf[0..w] };
    var out: [MAX_PACKET]u8 = undefined;
    const n1 = try readPacket(&ms, &out);
    try std.testing.expectEqualStrings("aaa", out[0..n1]);
    const n2 = try readPacket(&ms, &out);
    try std.testing.expectEqualStrings("bbbb", out[0..n2]);
    const n3 = try readPacket(&ms, &out);
    try std.testing.expectEqualStrings("c", out[0..n3]);
    // 流尽 → StreamClosed
    try std.testing.expectError(PacketError.StreamClosed, readPacket(&ms, &out));
}

test "udp packet: 0 长度包与超限包" {
    var buf: [8]u8 = .{ 0, 0, 0xFF, 0xFF, 1, 2, 3, 4 };
    var ms = MemStream{ .data = buf[0..4] };
    var out: [MAX_PACKET]u8 = undefined;
    try std.testing.expectEqual(@as(usize, 0), try readPacket(&ms, &out));
    // 长度 65535 > out.len → PacketTooBig
    var ms2 = MemStream{ .data = buf[2..] }; // 0xFF 0xFF 起头才是 65535
    try std.testing.expectError(PacketError.PacketTooBig, readPacket(&ms2, &out));
}
