//! 网络地址原语（上游 common/net 的服务端子集：Address/Port/Destination）。
//! 域名解析不做（freedom 直通系统栈 getaddrinfo）。

const std = @import("std");

pub const AddressFamily = enum(u8) {
    ipv4,
    ipv6,
    domain,

    pub fn isIP(self: AddressFamily) bool {
        return self == .ipv4 or self == .ipv6;
    }
};

pub const Address = union(enum) {
    ipv4: [4]u8,
    ipv6: [16]u8,
    domain: []const u8,

    pub fn family(self: Address) AddressFamily {
        return switch (self) {
            .ipv4 => .ipv4,
            .ipv6 => .ipv6,
            .domain => .domain,
        };
    }

    pub fn isIPv4(self: Address) bool {
        return self.family() == .ipv4;
    }

    pub fn isIPv6(self: Address) bool {
        return self.family() == .ipv6;
    }

    pub fn isIP(self: Address) bool {
        return self.family().isIP();
    }

    pub fn isDomain(self: Address) bool {
        return self.family() == .domain;
    }

    /// 上游 IPAddress()：v4-mapped IPv6（::ffff:a.b.c.d）折叠为 IPv4
    pub fn fromIpBytes(ip: []const u8) ?Address {
        return switch (ip.len) {
            4 => .{ .ipv4 = ip[0..4].* },
            16 => blk: {
                const all_zero_10 = [10]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
                if (std.mem.eql(u8, ip[0..10], all_zero_10[0..]) and ip[10] == 0xff and ip[11] == 0xff) {
                    break :blk .{ .ipv4 = ip[12..16].* };
                }
                break :blk .{ .ipv6 = ip[0..16].* };
            },
            else => null,
        };
    }

    /// 解析 IP 字面量；失败返回 null（调用方按域名处理——对齐上游 ParseAddress）
    pub fn parseIpLiteral(text_: []const u8) ?Address {
        var text = text_;
        // [2001:db8::1] 形式剥壳
        if (text.len >= 2 and text[0] == '[' and text[text.len - 1] == ']') {
            text = text[1 .. text.len - 1];
        }
        const Inet = std.Io.net;
        // 裸 IPv6（parseLiteral 要求带端口/括号，故含 ':' 的先走 Ip6Address.parse）
        if (std.mem.indexOfScalar(u8, text, ':') != null) {
            const p6 = Inet.Ip6Address.parse(text, 0) catch return null;
            return Address.fromIpBytes(p6.bytes[0..]) orelse null; // v4-mapped 折叠
        }
        const p4 = Inet.Ip4Address.parse(text, 0) catch return null;
        return .{ .ipv4 = p4.bytes };
    }

    /// 上游 ParseAddress：IP 字面量成功为 IP，否则视为域名
    pub fn parseAddress(text: []const u8) Address {
        if (parseIpLiteral(text)) |a| return a;
        return .{ .domain = text };
    }

    pub fn equals(self: Address, other: Address) bool {
        if (@as(AddressFamily, self.family()) != other.family()) return false;
        return switch (self) {
            .ipv4 => |a| std.mem.eql(u8, &a, &other.ipv4),
            .ipv6 => |a| std.mem.eql(u8, &a, &other.ipv6),
            .domain => |d| std.mem.eql(u8, d, other.domain),
        };
    }

    /// 格式化（不含端口）。返回写入长度。
    pub fn format(self: Address, buf: []u8) usize {
        switch (self) {
            .ipv4 => |b| {
                const s = std.fmt.bufPrint(buf, "{d}.{d}.{d}.{d}", .{ b[0], b[1], b[2], b[3] }) catch return 0;
                return s.len;
            },
            .ipv6 => |b| {
                const a = std.Io.net.Ip6Address{ .port = 0, .bytes = b };
                const s = std.fmt.bufPrint(buf, "{f}", .{&a}) catch return 0;
                const n = @min(s.len, buf.len);
                @memcpy(buf[0..n], s[0..n]);
                return n;
            },
            .domain => |d| {
                const n = @min(d.len, buf.len);
                @memcpy(buf[0..n], d[0..n]);
                return n;
            },
        }
    }
};

pub const Network = enum(u8) {
    tcp,
    udp,

    pub fn transferType(self: Network) []const u8 {
        return switch (self) {
            .tcp => "tcp",
            .udp => "udp",
        };
    }
};

pub const Destination = struct {
    network: Network = .tcp,
    address: Address,
    port: u16,

    /// Go Destination.IsValid：端口非 0 且地址非空
    pub fn isValid(self: Destination) bool {
        if (self.port == 0) return false;
        return switch (self.address) {
            .domain => |d| d.len > 0,
            else => true,
        };
    }

    pub fn equals(self: Destination, other: Destination) bool {
        return self.network == other.network and self.port == other.port and self.address.equals(other.address);
    }

    /// "tcp:1.2.3.4:443" 形态（日志用）
    pub fn format(self: Destination, buf: []u8) usize {
        var tmp: [96]u8 = undefined;
        const s = switch (self.address) {
            .ipv4 => |b| std.fmt.bufPrint(&tmp, "{s}:{d}.{d}.{d}.{d}:{d}", .{
                self.network.transferType(), b[0], b[1], b[2], b[3], self.port,
            }) catch return 0,
            .ipv6 => |b| std.fmt.bufPrint(&tmp, "{s}:[{f}]:{d}", .{
                self.network.transferType(), &std.Io.net.Ip6Address{ .port = 0, .bytes = b }, self.port,
            }) catch return 0,
            .domain => |d| std.fmt.bufPrint(&tmp, "{s}:{s}:{d}", .{ self.network.transferType(), d, self.port }) catch return 0,
        };
        const n = @min(s.len, buf.len);
        @memcpy(buf[0..n], s[0..n]);
        return n;
    }
};

pub const PortError = error{ InvalidPortRange, InvalidPortString };

/// PortFromBytes：大端 2 字节
pub fn portFromBytes(b: *const [2]u8) u16 {
    return std.mem.readInt(u16, b, .big);
}

pub fn portFromInt(v: u32) PortError!u16 {
    if (v > 65535) return PortError.InvalidPortRange;
    return @intCast(v);
}

pub fn portFromString(s: []const u8) PortError!u16 {
    const v = std.fmt.parseInt(u32, s, 10) catch return PortError.InvalidPortString;
    return portFromInt(v);
}

// ============================ 测试（上游 common/net 语义子集） ============================

test "address family property" {
    const a4 = Address{ .ipv4 = .{ 127, 0, 0, 1 } };
    try std.testing.expect(a4.isIPv4());
    try std.testing.expect(a4.isIP());
    try std.testing.expect(!a4.isDomain());
    const a6 = Address{ .ipv6 = [16]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 } };
    try std.testing.expect(a6.isIPv6());
    const ad = Address{ .domain = "www.example.com" };
    try std.testing.expect(ad.isDomain());
    try std.testing.expect(!ad.isIP());
}

test "parse address ip literal vs domain" {
    const Ip = Address;
    const a = Ip.parseAddress("8.8.8.8");
    try std.testing.expect(a.isIPv4());
    try std.testing.expectEqual([4]u8{ 8, 8, 8, 8 }, a.ipv4);
    const a6 = Ip.parseAddress("2001:db8::68");
    try std.testing.expect(a6.isIPv6());
    const d = Ip.parseAddress("www.example.com");
    try std.testing.expect(d.isDomain());
    try std.testing.expectEqualStrings("www.example.com", d.domain);
    // [::1] 剥壳
    const lo = Ip.parseAddress("[::1]");
    try std.testing.expect(lo.isIPv6());
    // v4-mapped 折叠
    const mapped = Ip.parseAddress("::ffff:1.2.3.4");
    try std.testing.expect(mapped.isIPv4());
    try std.testing.expectEqual([4]u8{ 1, 2, 3, 4 }, mapped.ipv4);
}

test "address format roundtrip" {
    var buf: [72]u8 = undefined;
    const a4 = Address{ .ipv4 = .{ 1, 2, 3, 4 } };
    const n4 = a4.format(buf[0..]);
    try std.testing.expectEqualStrings("1.2.3.4", buf[0..n4]);
    const d = Address{ .domain = "example.com" };
    const nd = d.format(buf[0..]);
    try std.testing.expectEqualStrings("example.com", buf[0..nd]);
}

test "destination format" {
    const d = Destination{ .network = .tcp, .address = .{ .domain = "www.example.com" }, .port = 443 };
    var buf: [80]u8 = undefined;
    const n = d.format(buf[0..]);
    try std.testing.expectEqualStrings("tcp:www.example.com:443", buf[0..n]);
}

test "port range" {
    try std.testing.expectEqual(@as(u16, 443), try portFromString("443"));
    try std.testing.expectError(PortError.InvalidPortRange, portFromString("65536"));
    try std.testing.expectError(PortError.InvalidPortString, portFromString("abc"));
    const b = [2]u8{ 0x01, 0xBB };
    try std.testing.expectEqual(@as(u16, 443), portFromBytes(&b));
}

test "address equals" {
    const a = Address{ .ipv4 = .{ 1, 2, 3, 4 } };
    const b = Address{ .ipv4 = .{ 1, 2, 3, 4 } };
    const c = Address{ .domain = "1.2.3.4" };
    try std.testing.expect(a.equals(b));
    try std.testing.expect(!a.equals(c));
}
