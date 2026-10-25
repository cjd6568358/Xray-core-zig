//! M8 VMess 编码层测试（移植上游 proxy/vmess/encoding/encoding_test.go：
//! TestRequestSerialization / TestInvalidRequest / TestMuxRequest）。
//!
//! 路径：encodeRequestHeader（客户端序列化）→ decodeRequestHeader（服务端解析）。
//! M7 已覆盖密封头/分块体全链；此处补编解码 roundtrip 与拒绝路径，
//! 另移植 server.go parseSecurityType 的枚举名映射（inbound 拒绝文案用）。

const std = @import("std");
const vmess_enc = @import("../src/proxy/vmess/encoding.zig");
const net = @import("../src/common/net.zig");

test "vmess: 请求头 roundtrip（domain/ipv4/ipv6 + padding；上游 TestRequestSerialization）" {
    const iv = [16]u8{ 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00 };
    const key = [16]u8{ 0xde, 0xad, 0xbe, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98 };
    const dests = [_]net.Destination{
        .{ .network = .tcp, .address = .{ .domain = "www.example.com" }, .port = 443 },
        .{ .network = .tcp, .address = .{ .ipv4 = .{ 127, 0, 0, 1 } }, .port = 80 },
        .{ .network = .tcp, .address = .{ .ipv6 = .{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 } }, .port = 8443 },
    };
    for (dests) |dest| {
        var buf: [256]u8 = undefined;
        const n = vmess_enc.encodeRequestHeader(buf[0..], &iv, &key, 0x5A, 0x1C, 0, 0x03, vmess_enc.Cmd.tcp, dest, 0);
        const h = try vmess_enc.decodeRequestHeader(buf[0..n]);
        try std.testing.expectEqual(@as(u8, 1), h.version);
        try std.testing.expectEqualSlices(u8, &iv, &h.request_iv);
        try std.testing.expectEqualSlices(u8, &key, &h.request_key);
        try std.testing.expectEqual(@as(u8, 0x5A), h.response_header);
        try std.testing.expectEqual(@as(u8, 0x1C), h.option);
        try std.testing.expectEqual(@as(u8, 0x03), h.security);
        try std.testing.expectEqual(@as(u8, 0), h.padding_len);
        try std.testing.expectEqual(vmess_enc.Cmd.tcp, h.command);
        try std.testing.expectEqual(dest.port, h.dest.?.port);
        switch (dest.address) {
            .domain => |d| try std.testing.expectEqualStrings(d, h.dest.?.address.domain),
            .ipv4 => |b| try std.testing.expectEqualSlices(u8, &b, &h.dest.?.address.ipv4),
            .ipv6 => |b| try std.testing.expectEqualSlices(u8, &b, &h.dest.?.address.ipv6),
        }
    }
}

test "vmess: 请求头 padding>0 roundtrip（padding 字节不进字段但参与 FNV）" {
    const iv: [16]u8 = @splat(0x11);
    const key: [16]u8 = @splat(0x22);
    var buf: [256]u8 = undefined;
    const dest = net.Destination{ .network = .tcp, .address = .{ .domain = "example.com" }, .port = 443 };
    const n = vmess_enc.encodeRequestHeader(buf[0..], &iv, &key, 0x33, 0x04, 5, 0x03, vmess_enc.Cmd.tcp, dest, 0xAA);
    const h = try vmess_enc.decodeRequestHeader(buf[0..n]);
    try std.testing.expectEqual(@as(u8, 5), h.padding_len);
    try std.testing.expectEqualStrings("example.com", h.dest.?.address.domain);
}

test "vmess: FNV 篡改 / 坏版本 / 地址畸形 → 拒绝" {
    const iv: [16]u8 = @splat(0x11);
    const key: [16]u8 = @splat(0x22);
    const dest = net.Destination{ .network = .tcp, .address = .{ .ipv4 = .{ 127, 0, 0, 1 } }, .port = 80 };
    var buf: [256]u8 = undefined;
    const n = vmess_enc.encodeRequestHeader(buf[0..], &iv, &key, 0x33, 0x04, 0, 0x03, vmess_enc.Cmd.tcp, dest, 0);

    // FNV 尾篡改 1 字节
    {
        var bad = buf;
        bad[n - 1] ^= 0x01;
        try std.testing.expectError(error.FnvMismatch, vmess_enc.decodeRequestHeader(bad[0..n]));
    }
    // 版本字节改 2
    {
        var bad = buf;
        bad[0] = 0x02;
        // 版本变了 FNV 也会挂——先修 FNV 再验版本错（按字段顺序版本先判）
        const h2_len = n; // 直接验：版本优先于 FNV
        _ = h2_len;
        try std.testing.expectError(error.InvalidVersion, vmess_enc.decodeRequestHeader(bad[0..n]));
    }
    // 地址类型字节改 9（未知）
    {
        var bad = buf;
        bad[n - 4 - 5] = 0x09; // FNV(4) 之前是 v4(4)，其前是 atype(1)
        try std.testing.expectError(error.InvalidAddress, vmess_enc.decodeRequestHeader(bad[0..n]));
    }
    // 地址段截断（整体砍 3 字节 → 不足 41 或地址读不全）
    {
        try std.testing.expectError(error.HeaderTooShort, vmess_enc.decodeRequestHeader(buf[0 .. n - 3]));
    }
}

test "vmess: Mux command → dest null（上游 TestMuxRequest；地址段不写）" {
    const iv: [16]u8 = @splat(0x11);
    const key: [16]u8 = @splat(0x22);
    var buf: [256]u8 = undefined;
    const n = vmess_enc.encodeRequestHeader(buf[0..], &iv, &key, 0x33, 0x04, 0, 0x03, vmess_enc.Cmd.mux, .{ .network = .tcp, .address = .{ .domain = "v1.mux.cool" }, .port = 0 }, 0);
    const h = try vmess_enc.decodeRequestHeader(buf[0..n]);
    try std.testing.expectEqual(vmess_enc.Cmd.mux, h.command);
    try std.testing.expect(h.dest == null);
}

test "vmess: securityTypeName 映射（server.go parseSecurityType + SecurityType_name）" {
    // 0/2 → AUTO（0 经 UNKNOWN→AUTO 兼容改写）；3/4 具名；其余 UNKNOWN
    try std.testing.expectEqualStrings("AUTO", vmess_enc.securityTypeName(0x00));
    try std.testing.expectEqualStrings("AUTO", vmess_enc.securityTypeName(0x02));
    try std.testing.expectEqualStrings("AES128_GCM", vmess_enc.securityTypeName(0x03));
    try std.testing.expectEqualStrings("CHACHA20_POLY1305", vmess_enc.securityTypeName(0x04));
    try std.testing.expectEqualStrings("UNKNOWN", vmess_enc.securityTypeName(0x05)); // NONE 已删
    try std.testing.expectEqualStrings("UNKNOWN", vmess_enc.securityTypeName(0x01));
    try std.testing.expectEqualStrings("UNKNOWN", vmess_enc.securityTypeName(0x63));
}

test "vmess: option 标志位解码（chunk_masking/global_padding/auth_len/chunk_stream）" {
    const iv: [16]u8 = @splat(0x11);
    const key: [16]u8 = @splat(0x22);
    const dest = net.Destination{ .network = .tcp, .address = .{ .ipv4 = .{ 127, 0, 0, 1 } }, .port = 80 };
    var buf: [256]u8 = undefined;
    const option: u8 = vmess_enc.RequestOption.chunk_stream |
        vmess_enc.RequestOption.chunk_masking |
        vmess_enc.RequestOption.global_padding |
        vmess_enc.RequestOption.authenticated_length;
    const n = vmess_enc.encodeRequestHeader(buf[0..], &iv, &key, 0x33, option, 0, 0x04, vmess_enc.Cmd.tcp, dest, 0);
    const h = try vmess_enc.decodeRequestHeader(buf[0..n]);
    try std.testing.expectEqual(option, h.option);
    try std.testing.expect(h.option & vmess_enc.RequestOption.chunk_stream != 0);
    try std.testing.expect(h.option & vmess_enc.RequestOption.chunk_masking != 0);
    try std.testing.expect(h.option & vmess_enc.RequestOption.global_padding != 0);
    try std.testing.expect(h.option & vmess_enc.RequestOption.authenticated_length != 0);
}
