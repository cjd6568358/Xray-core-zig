//! WebSocket 帧编解码原语（RFC 6455 服务端子集；对照 gorilla/websocket v1.5.3
//! 在 xray transport/internet/websocket/connection.go 路径上的可观测行为）。
//!
//! 帧子集（§5.9）：数据帧 opcode 0x0/0x1/0x2 顺序拼接为字节流（分片重组）；
//! 控制帧 Ping/Pong/Close；客户端帧必须带 mask（服务端帧不带）；RSV≠0 断开。

const std = @import("std");

pub const opcode_continuation: u4 = 0x0;
pub const opcode_text: u4 = 0x1;
pub const opcode_binary: u4 = 0x2;
pub const opcode_close: u4 = 0x8;
pub const opcode_ping: u4 = 0x9;
pub const opcode_pong: u4 = 0xA;

/// RFC 6455 关闭码
pub const close_normal: u16 = 1000;
pub const close_going_away: u16 = 1001;
pub const close_protocol_error: u16 = 1002;
pub const close_no_status: u16 = 1005; // 不上线
pub const close_too_big: u16 = 1009;

pub const FrameError = error{
    Protocol, // RSV/保留 opcode/无 mask/控制帧越界/分片错序
    TooBig, // 载荷超安全上限
    Closed, // 对端已关（Close 帧或 TCP EOF）
    Timeout,
};

pub const Header = struct {
    fin: bool,
    opcode: u4,
    masked: bool,
    length: u64,

    pub fn isControl(self: Header) bool {
        return (self.opcode & 0x8) != 0;
    }
};

/// 解析 2 字节基本头（扩展长度与 mask key 由调用方续读）
pub fn parseBase(b0: u8, b1: u8) Header {
    return .{
        .fin = (b0 & 0x80) != 0,
        .opcode = @intCast(b0 & 0x0F),
        .masked = (b1 & 0x80) != 0,
        .length = b1 & 0x7F,
    };
}

/// 编码服务端帧头（不带 mask）。返回写入 out 的字节数。
pub fn encodeHeader(fin: bool, opcode: u4, payload_len: usize, out: *[10]u8) usize {
    var n: usize = 0;
    out[0] = @as(u8, if (fin) 0x80 else 0x00) | @as(u8, opcode);
    n = 1;
    if (payload_len < 126) {
        out[1] = @intCast(payload_len);
        n += 1;
    } else if (payload_len <= 0xFFFF) {
        out[1] = 126;
        std.mem.writeInt(u16, out[2..4], @intCast(payload_len), .big);
        n += 3;
    } else {
        out[1] = 127;
        std.mem.writeInt(u64, out[2..10], payload_len, .big);
        n += 9;
    }
    return n;
}

/// 按帧内偏移 unmask（XOR；分片续传时传 offset = 已处理字节数 % 4）
pub fn unmask(data: []u8, key: [4]u8, offset: usize) void {
    for (data, 0..) |*c, i| {
        c.* ^= key[(i + offset) & 3];
    }
}

/// gorilla isValidReceivedCloseCode：接收侧校验（1004/1005/1006/1015/1016-2999/≥5000 不可上线）
pub fn isValidReceivedCloseCode(code: u16) bool {
    if (code >= 3000 and code <= 4999) return true;
    return switch (code) {
        1000, 1001, 1002, 1003, 1007, 1008, 1009, 1010, 1011, 1012, 1013, 1014 => true,
        else => false,
    };
}

/// gorilla FormatCloseMessage：仅 1005 → 空载荷（1005 不得上线）；其余原样编码
pub fn formatClosePayload(out: []u8, code: u16) []const u8 {
    if (code == close_no_status) {
        return out[0..0];
    }
    std.mem.writeInt(u16, out[0..2], code, .big);
    return out[0..2];
}

// ============================ 测试 ============================

test "header base parse" {
    const h = parseBase(0x82, 0x85); // FIN+binary, masked, len 5
    try std.testing.expect(h.fin);
    try std.testing.expectEqual(opcode_binary, h.opcode);
    try std.testing.expect(h.masked);
    try std.testing.expectEqual(@as(u64, 5), h.length);
    const h2 = parseBase(0x01, 0x7E); // text, no mask, 126 → extended
    try std.testing.expectEqual(@as(u64, 126), h2.length);
    try std.testing.expect(!h2.masked);
}

test "header encode roundtrip (server frame, no mask)" {
    var out: [10]u8 = undefined;
    // 小载荷
    var n = encodeHeader(true, opcode_binary, 5, &out);
    try std.testing.expectEqualSlices(u8, &.{ 0x82, 0x05 }, out[0..n]);
    // 16 位扩展
    n = encodeHeader(true, opcode_binary, 300, &out);
    try std.testing.expectEqualSlices(u8, &.{ 0x82, 126, 0x01, 0x2C }, out[0..n]);
    const h = parseBase(out[0], out[1]);
    try std.testing.expectEqual(@as(u64, 126), h.length);
    // 64 位扩展
    const big: usize = 70000;
    n = encodeHeader(false, opcode_text, big, &out);
    try std.testing.expectEqualSlices(u8, &.{ 0x01, 127, 0, 0, 0, 0, 0, 0x01, 0x11, 0x70 }, out[0..n]);
    // 65535 边界
    n = encodeHeader(true, opcode_binary, 0xFFFF, &out);
    try std.testing.expectEqualSlices(u8, &.{ 0x82, 126, 0xFF, 0xFF }, out[0..n]);
    n = encodeHeader(true, opcode_binary, 0x10000, &out);
    try std.testing.expectEqualSlices(u8, &.{ 0x82, 127, 0, 0, 0, 0, 0, 0x01, 0x00, 0x00 }, out[0..n]);
}

test "unmask with offset continuation" {
    var data = [6]u8{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
    const key = [4]u8{ 0x0F, 0xF0, 0x55, 0xAA };
    unmask(data[0..4], key, 0);
    try std.testing.expectEqualSlices(u8, &.{ 0x0F, 0xF0, 0x55, 0xAA }, data[0..4]);
    // 第二段续 4 字节偏移 0 → 同 key 循环；offset 1 续偏移
    var d2 = [2]u8{ 0, 0 };
    unmask(d2[0..2], key, 4);
    try std.testing.expectEqualSlices(u8, &.{ 0x0F, 0xF0 }, d2[0..]);
    var d3 = [2]u8{ 0, 0 };
    unmask(d3[0..2], key, 1);
    try std.testing.expectEqualSlices(u8, &.{ 0xF0, 0x55 }, d3[0..]);
}

test "format close payload" {
    var buf: [2]u8 = undefined;
    try std.testing.expectEqualSlices(u8, &.{ 0x03, 0xE8 }, formatClosePayload(&buf, 1000));
    try std.testing.expectEqualSlices(u8, &.{ 0x03, 0xEA }, formatClosePayload(&buf, 1002));
    try std.testing.expectEqualSlices(u8, &.{}, formatClosePayload(&buf, 1005));
    try std.testing.expectEqualSlices(u8, &.{ 0x0B, 0xB8 }, formatClosePayload(&buf, 3000));
    // 接收侧校验（gorilla validReceivedCloseCodes）
    try std.testing.expect(isValidReceivedCloseCode(1000));
    try std.testing.expect(isValidReceivedCloseCode(1009));
    try std.testing.expect(isValidReceivedCloseCode(3000));
    try std.testing.expect(isValidReceivedCloseCode(4999));
    try std.testing.expect(!isValidReceivedCloseCode(1005));
    try std.testing.expect(!isValidReceivedCloseCode(1006));
    try std.testing.expect(!isValidReceivedCloseCode(1015));
    try std.testing.expect(!isValidReceivedCloseCode(1016));
    try std.testing.expect(!isValidReceivedCloseCode(5000));
    try std.testing.expect(!isValidReceivedCloseCode(999));
}
