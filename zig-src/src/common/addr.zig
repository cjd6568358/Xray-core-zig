//! 地址编解码（VLESS/VMess 共用：端口在前 + 类型 1=IPv4 / 2=域名 / 3=IPv6）。
//! 对照上游 common/protocol/address.go 的 PortThenAddress 序列化。

const std = @import("std");
const net = @import("net.zig");

pub const AddrError = error{
    UnknownAddressType,
    TruncatedInput,
    DomainTooLong,
    NoSpace,
};

/// 写入：2B BE 端口 + 1B 类型 + 载荷。返回写入长度。
pub fn writePortThenAddress(out: []u8, dest: net.Destination) usize {
    var w: usize = 0;
    std.mem.writeInt(u16, out[0..2], dest.port, .big);
    w += 2;
    switch (dest.address) {
        .ipv4 => |b| {
            out[w] = 0x01;
            w += 1;
            out[w..][0..4].* = b;
            w += 4;
        },
        .domain => |d| {
            out[w] = 0x02;
            w += 1;
            out[w] = @intCast(d.len);
            w += 1;
            @memcpy(out[w..][0..d.len], d);
            w += d.len;
        },
        .ipv6 => |b| {
            out[w] = 0x03;
            w += 1;
            out[w..][0..16].* = b;
            w += 16;
        },
    }
    return w;
}

/// 读取：与写入对称。arena 非 null 时域名拷贝进 arena（连接生命周期），
/// 为 null 时域名直接引用输入缓冲（调用方须保证缓冲存活）。
pub fn readPortThenAddress(data: []const u8, pos: *usize, arena: ?std.mem.Allocator) AddrError!net.Destination {
    var r = pos.*;
    if (data.len < r + 2) return AddrError.TruncatedInput;
    const port = std.mem.readInt(u16, data[r..][0..2], .big);
    r += 2;
    if (data.len < r + 1) return AddrError.TruncatedInput;
    const addr_type = data[r];
    r += 1;
    var address: net.Address = undefined;
    switch (addr_type) {
        0x01 => {
            if (data.len < r + 4) return AddrError.TruncatedInput;
            address = .{ .ipv4 = data[r..][0..4].* };
            r += 4;
        },
        0x02 => {
            if (data.len < r + 1) return AddrError.TruncatedInput;
            const dl = data[r];
            r += 1;
            if (dl == 0) return AddrError.DomainTooLong; // 上游 domain 长度 1..=255
            if (data.len < r + dl) return AddrError.TruncatedInput;
            const raw = data[r..][0..dl];
            r += dl;
            if (arena) |a| {
                const copy = a.alloc(u8, dl) catch return AddrError.NoSpace;
                @memcpy(copy, raw);
                address = .{ .domain = copy };
            } else {
                address = .{ .domain = raw };
            }
        },
        0x03 => {
            if (data.len < r + 16) return AddrError.TruncatedInput;
            address = .{ .ipv6 = data[r..][0..16].* };
            r += 16;
        },
        else => return AddrError.UnknownAddressType,
    }
    pos.* = r;
    return .{ .network = .tcp, .address = address, .port = port };
}

test "port-then-address roundtrip all families" {
    const dests = [_]net.Destination{
        .{ .network = .tcp, .address = .{ .ipv4 = .{ 1, 2, 3, 4 } }, .port = 443 },
        .{ .network = .tcp, .address = .{ .domain = "www.example.com" }, .port = 80 },
        .{ .network = .udp, .address = .{ .ipv6 = [16]u8{ 0x20, 1, 0xdb, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x68 } }, .port = 53 },
    };
    var buf: [256]u8 = undefined;
    for (dests) |d| {
        const n = writePortThenAddress(buf[0..], d);
        var pos: usize = 0;
        const back = try readPortThenAddress(buf[0..n], &pos, null);
        // 编解码只承载 port+address（network 由协议 command 决定）
        try std.testing.expect(d.address.equals(back.address) and d.port == back.port);
        const want_type: u8 = switch (d.address) {
            .ipv4 => 0x01,
            .domain => 0x02,
            .ipv6 => 0x03,
        };
        try std.testing.expectEqual(want_type, buf[2]);
    }
}

test "bad address type rejected" {
    var buf = [8]u8{ 0x01, 0xBB, 0x10, 0, 0, 0, 0, 0 };
    var pos: usize = 0;
    try std.testing.expectError(AddrError.UnknownAddressType, readPortThenAddress(buf[0..], &pos, null));
    pos = 0;
    buf[2] = 0x01; // v4 但数据不足
    try std.testing.expectError(AddrError.TruncatedInput, readPortThenAddress(buf[0..5], &pos, null));
}
