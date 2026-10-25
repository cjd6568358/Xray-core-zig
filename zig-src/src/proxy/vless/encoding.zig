//! VLESS 编码层（上游 proxy/vless/encoding/encoding.go 服务端方向子集）。
//! M1：请求头序列化（黄金向量锚定）。M5 补：解析 + validator。

const std = @import("std");
const net = @import("../../common/net.zig");
const addr = @import("../../common/addr.zig");
const uuid = @import("../../common/uuid.zig");

pub const version_0: u8 = 0x00;

pub const Command = struct {
    pub const tcp: u8 = 0x01;
    pub const udp: u8 = 0x02;
    pub const mux: u8 = 0x03;
    pub const rvs: u8 = 0x04;
};

/// 请求头序列化（对照 encoding.go:30-61）：version(0) uuid16 addonsLen(0) command port(BE) address
pub fn encodeRequestHeader(out: []u8, u: uuid.Uuid, command: u8, dest: net.Destination) usize {
    var w: usize = 0;
    out[w] = version_0;
    w += 1;
    out[w..][0..16].* = u.bytes;
    w += 16;
    out[w] = 0x00; // addons 长度（本配置 flow 空 → 恒 0）
    w += 1;
    out[w] = command;
    w += 1;
    if (command != Command.mux and command != Command.rvs) {
        w += addr.writePortThenAddress(out[w..], dest);
    }
    return w;
}

test "vless header size shape" {
    const u = try uuid.Uuid.parse("de53e864-8530-4212-a3d7-c31e60b62e91");
    var buf: [64]u8 = undefined;
    const n = encodeRequestHeader(buf[0..], u, Command.tcp, .{
        .network = .tcp,
        .address = .{ .domain = "www.example.com" },
        .port = 443,
    });
    // 1 + 16 + 1 + 1 + 2 + 1 + 1 + 15 = 38
    try std.testing.expectEqual(@as(usize, 38), n);
}
