//! M8 VLESS 编码层测试（移植上游 proxy/vless/encoding/encoding_test.go：
//! TestRequestSerialization / TestInvalidRequest / TestMuxRequest）。
//!
//! 路径：encodeRequestHeader（客户端序列化）→ HeadReader.fromSlice（纯内存源）
//! → parseHeader（服务端解析）。黄金向量（M1）锚定线格式，此处补边界与拒绝路径。

const std = @import("std");
const vless_enc = @import("../src/proxy/vless/encoding.zig");
const vless_in = @import("../src/proxy/vless/inbound.zig");
const conf_vless = @import("../src/conf/vless.zig");
const net = @import("../src/common/net.zig");

const test_uuid_str = "de53e864-8530-4212-a3d7-c31e60b62e91";

fn testUsers(arena: std.mem.Allocator) []conf_vless.VlessClient.Built {
    const users = arena.alloc(conf_vless.VlessClient.Built, 1) catch unreachable;
    users[0] = (conf_vless.VlessClient{ .id = test_uuid_str, .email = "pb8lpgli" }).build() catch unreachable;
    return users;
}

test "vless: 请求头 roundtrip（domain / ipv4 / ipv6；上游 TestRequestSerialization）" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const users = testUsers(arena);
    const dests = [_]net.Destination{
        .{ .network = .tcp, .address = .{ .domain = "www.example.com" }, .port = 443 },
        .{ .network = .tcp, .address = .{ .ipv4 = .{ 192, 168, 1, 1 } }, .port = 80 },
        .{ .network = .tcp, .address = .{ .ipv6 = .{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 } }, .port = 8443 },
    };
    for (dests) |dest| {
        var buf: [128]u8 = undefined;
        const n = vless_enc.encodeRequestHeader(buf[0..], users[0].uuid, vless_enc.Command.tcp, dest);
        var hr = vless_in.HeadReader.fromSlice(arena, buf[0..n]);
        const req = try vless_in.parseHeader(&hr, users);
        try std.testing.expectEqual(@as(u8, 0x01), req.command);
        try std.testing.expectEqual(dest.port, req.dest.port);
        try std.testing.expectEqual(dest.network, req.dest.network);
        try std.testing.expectEqualStrings("pb8lpgli", req.user.email);
        try std.testing.expectEqualStrings("", req.flow);
        switch (dest.address) {
            .domain => |d| {
                try std.testing.expect(req.dest.address.family() == .domain);
                try std.testing.expectEqualStrings(d, req.dest.address.domain);
            },
            .ipv4 => |b| try std.testing.expectEqualSlices(u8, &b, &req.dest.address.ipv4),
            .ipv6 => |b| try std.testing.expectEqualSlices(u8, &b, &req.dest.address.ipv6),
        }
        // 预读应被完整消费（无残留字节）
        try std.testing.expectEqual(n, hr.pos);
    }
}

test "vless: 坏版本 / 未知用户 / 未知地址类型 / UDP command（上游 TestInvalidRequest 路径集）" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const users = testUsers(arena);

    // 坏版本（version=1）
    {
        var buf: [64]u8 = undefined;
        const n = vless_enc.encodeRequestHeader(buf[0..], users[0].uuid, vless_enc.Command.tcp, .{ .network = .tcp, .address = .{ .ipv4 = .{ 127, 0, 0, 1 } }, .port = 1 });
        buf[0] = 0x01;
        var hr = vless_in.HeadReader.fromSlice(arena, buf[0..n]);
        try std.testing.expectError(vless_in.ParseError.InvalidVersion, vless_in.parseHeader(&hr, users));
    }
    // 未知用户（UUID 改一个字节）
    {
        var buf: [64]u8 = undefined;
        const n = vless_enc.encodeRequestHeader(buf[0..], users[0].uuid, vless_enc.Command.tcp, .{ .network = .tcp, .address = .{ .ipv4 = .{ 127, 0, 0, 1 } }, .port = 1 });
        buf[3] ^= 0xFF;
        var hr = vless_in.HeadReader.fromSlice(arena, buf[0..n]);
        try std.testing.expectError(vless_in.ParseError.InvalidUserId, vless_in.parseHeader(&hr, users));
    }
    // 未知地址类型（atype=9）
    {
        var buf: [64]u8 = undefined;
        const n = vless_enc.encodeRequestHeader(buf[0..], users[0].uuid, vless_enc.Command.tcp, .{ .network = .tcp, .address = .{ .ipv4 = .{ 127, 0, 0, 1 } }, .port = 1 });
        buf[n - 5] = 0x09; // 端口(2)+类型(1)+v4(4) 的 type 字节
        var hr = vless_in.HeadReader.fromSlice(arena, buf[0..n]);
        try std.testing.expectError(vless_in.ParseError.InvalidAddress, vless_in.parseHeader(&hr, users));
    }
    // command=100（上游 TestInvalidRequest）：非 TCP/UDP → 不读地址段。
    // 注意上游同款不对称：客户端编码器对非 Mux 命令**会写**地址（encoding.go:53），
    // 服务端解析器只对 TCP/UDP 读地址——残留字节留在流里（随后连接被拒）。
    {
        var buf: [64]u8 = undefined;
        const n = vless_enc.encodeRequestHeader(buf[0..], users[0].uuid, 100, .{ .network = .tcp, .address = .{ .ipv4 = .{ 127, 0, 0, 1 } }, .port = 1 });
        try std.testing.expectEqual(@as(usize, 26), n); // 19 + 端口2 + 类型1 + v4(4)
        var hr = vless_in.HeadReader.fromSlice(arena, buf[0..n]);
        const req = try vless_in.parseHeader(&hr, users);
        try std.testing.expectEqual(@as(u8, 100), req.command);
        try std.testing.expectEqual(@as(usize, 19), hr.pos); // 只消费定长部分
    }
}

test "vless: Mux command 不写地址段（上游 TestMuxRequest；本版 dest 由调用方拒绝）" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const users = testUsers(arena);

    var buf: [64]u8 = undefined;
    const n = vless_enc.encodeRequestHeader(buf[0..], users[0].uuid, vless_enc.Command.mux, .{ .network = .tcp, .address = .{ .domain = "v1.mux.cool" }, .port = 0 });
    var hr = vless_in.HeadReader.fromSlice(arena, buf[0..n]);
    const req = try vless_in.parseHeader(&hr, users);
    try std.testing.expectEqual(@as(u8, 0x03), req.command);
    try std.testing.expectEqual(n, hr.pos); // 地址段未写入/未消费
}

test "vless: addons Flow 提取 + 未知字段跳过 + 畸形拒绝" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const users = testUsers(arena);

    // 手工构造：version(0) uuid(16) addonsLen(1) addons command(1) port(2) atype(1) v4(4)
    // addons = [field1,len,Flow字节...][field2,len,Seed 8B][field5 fixed32 4B]
    const flow_s = "xtls-rprx-vision";
    var addons: [64]u8 = undefined;
    var al: usize = 0;
    addons[al] = (1 << 3) | 2;
    al += 1; // field 1, wire 2
    addons[al] = flow_s.len;
    al += 1;
    @memcpy(addons[al..][0..flow_s.len], flow_s);
    al += flow_s.len;
    addons[al] = (2 << 3) | 2;
    al += 1; // field 2 (Seed), wire 2 → 跳过
    addons[al] = 8;
    al += 1;
    @memset(addons[al..][0..8], 0xAB);
    al += 8;
    addons[al] = (5 << 3) | 5;
    al += 1; // field 5, wire 5 (fixed32) → 跳过
    @memset(addons[al..][0..4], 0xCD);
    al += 4;

    var buf: [128]u8 = undefined;
    var w: usize = 0;
    buf[w] = 0;
    w += 1;
    @memcpy(buf[w..][0..16], &users[0].uuid.bytes);
    w += 16;
    buf[w] = @intCast(al);
    w += 1;
    @memcpy(buf[w..][0..al], addons[0..al]);
    w += al;
    buf[w] = vless_enc.Command.tcp;
    w += 1;
    std.mem.writeInt(u16, buf[w..][0..2], 443, .big);
    w += 2;
    buf[w] = 0x01;
    w += 1;
    @memcpy(buf[w..][0..4], &[_]u8{ 127, 0, 0, 1 });
    w += 4;

    var hr = vless_in.HeadReader.fromSlice(arena, buf[0..w]);
    const req = try vless_in.parseHeader(&hr, users);
    try std.testing.expectEqualStrings(flow_s, req.flow);

    // 畸形 addons：长度字节声明 10，但实际只给 3 字节 → 流在 addons 中途结束
    // （parseAddonsFlow 越过 pre 末端 → EndOfStream；上游 proto.Unmarshal 同为 unexpected EOF）
    var bad: [32]u8 = undefined;
    var bw: usize = 0;
    bad[bw] = 0;
    bw += 1;
    @memcpy(bad[bw..][0..16], &users[0].uuid.bytes);
    bw += 16;
    bad[bw] = 10;
    bw += 1; // addonsLen = 10
    bad[bw] = (1 << 3) | 2;
    bw += 1;
    bad[bw] = 1;
    bw += 1;
    bad[bw] = 0x58;
    bw += 1; // 只提供了 3 字节 addons 内容（< 10）
    var hr2 = vless_in.HeadReader.fromSlice(arena, bad[0..bw]);
    try std.testing.expectError(vless_in.ParseError.EndOfStream, vless_in.parseHeader(&hr2, users));

    // 畸形 addons：length-delimited 长度超过剩余 → BadAddons（l > remaining 检查）
    var bad3: [32]u8 = undefined;
    var bw3: usize = 0;
    bad3[bw3] = 0;
    bw3 += 1;
    @memcpy(bad3[bw3..][0..16], &users[0].uuid.bytes);
    bw3 += 16;
    bad3[bw3] = 3;
    bw3 += 1; // addonsLen = 3
    bad3[bw3] = (1 << 3) | 2;
    bw3 += 1;
    bad3[bw3] = 20;
    bw3 += 1; // 声明 20B 载荷但 addons 只剩 1B
    bad3[bw3] = 0x41;
    bw3 += 1;
    var hr4 = vless_in.HeadReader.fromSlice(arena, bad3[0..bw3]);
    try std.testing.expectError(vless_in.ParseError.BadAddons, vless_in.parseHeader(&hr4, users));

    // 畸形 addons：未知 wire type（3/4）→ BadAddons
    var bad2: [32]u8 = undefined;
    var bw2: usize = 0;
    bad2[bw2] = 0;
    bw2 += 1;
    @memcpy(bad2[bw2..][0..16], &users[0].uuid.bytes);
    bw2 += 16;
    bad2[bw2] = 1;
    bw2 += 1; // addonsLen = 1
    bad2[bw2] = (1 << 3) | 3;
    bw2 += 1; // wire 3 (start group) → 不支持
    var hr3 = vless_in.HeadReader.fromSlice(arena, bad2[0..bw2]);
    try std.testing.expectError(vless_in.ParseError.BadAddons, vless_in.parseHeader(&hr3, users));
}

test "vless: 头中途 EOF → EndOfStream（对端关，静默）" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const users = testUsers(arena);

    var buf: [64]u8 = undefined;
    const n = vless_enc.encodeRequestHeader(buf[0..], users[0].uuid, vless_enc.Command.tcp, .{ .network = .tcp, .address = .{ .domain = "www.example.com" }, .port = 443 });
    // 截断在地址段中间（少 5 字节）
    var hr = vless_in.HeadReader.fromSlice(arena, buf[0 .. n - 5]);
    try std.testing.expectError(vless_in.ParseError.EndOfStream, vless_in.parseHeader(&hr, users));
}
