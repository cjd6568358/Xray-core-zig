//! UUID（上游 common/uuid/uuid.go 全量语义）：
//! 36/32 位标准形态解析；1–30 字符短串 = SHA1(全零UUID || str)[:16] 置 v5 位。

const std = @import("std");

pub const Uuid = struct {
    bytes: [16]u8,

    pub const ParseError = error{InvalidUuid};

    /// ParseString：l ∈ [32,36] 走分组解析；l ∈ [1,30] 走 SHA1 短串；其余报错
    pub fn parse(str: []const u8) ParseError!Uuid {
        var u = Uuid{ .bytes = @splat(0) };

        const l = str.len;
        if (l < 32 or l > 36) {
            if (l == 0 or l > 30) return ParseError.InvalidUuid;
            var h = std.crypto.hash.Sha1.init(.{});
            h.update(u.bytes[0..]); // 全零 UUID（上游即此语义）
            h.update(str);
            var digest: [20]u8 = undefined;
            h.final(&digest);
            @memcpy(u.bytes[0..], digest[0..16]);
            u.bytes[6] = (u.bytes[6] & 0x0f) | (5 << 4);
            u.bytes[8] = (u.bytes[8] & 0x3f) | (0x02 << 6);
            return u;
        }

        const byte_groups = [_]usize{ 8, 4, 4, 4, 12 };
        var text = str;
        var out: usize = 0;
        for (byte_groups) |group| {
            if (text.len > 0 and text[0] == '-') text = text[1..];
            if (text.len < group) return ParseError.InvalidUuid;
            _ = std.fmt.hexToBytes(u.bytes[out .. out + group / 2], text[0..group]) catch
                return ParseError.InvalidUuid;
            text = text[group..];
            out += group / 2;
        }
        return u;
    }

    pub fn fromBytes(b: []const u8) ParseError!Uuid {
        if (b.len != 16) return ParseError.InvalidUuid;
        return .{ .bytes = b[0..16].* };
    }

    pub fn equals(self: Uuid, other: Uuid) bool {
        return std.mem.eql(u8, self.bytes[0..], other.bytes[0..]);
    }

    /// 小写 8-4-4-4-12 格式化。buf.len >= 36。
    pub fn format(self: Uuid, buf: []u8) []const u8 {
        const hexdig = "0123456789abcdef";
        const groups = [_]usize{ 4, 2, 2, 2, 6 }; // 每组字节数
        var w: usize = 0;
        var bi: usize = 0;
        for (groups, 0..) |n, gi| {
            if (gi > 0) {
                buf[w] = '-';
                w += 1;
            }
            for (0..n) |i| {
                const b = self.bytes[bi + i];
                buf[w] = hexdig[b >> 4];
                buf[w + 1] = hexdig[b & 0x0f];
                w += 2;
            }
            bi += n;
            w += 0;
        }
        return buf[0..w];
    }
};

pub fn cmdKeyOf(u: Uuid) [16]u8 {
    // 上游 common/protocol/id.go：cmdKey = MD5(uuid || "c48619fe-8f02-49e0-b9e9-edf763e17e21")
    var out: [16]u8 = undefined;
    var h = std.crypto.hash.Md5.init(.{});
    h.update(u.bytes[0..]);
    h.update("c48619fe-8f02-49e0-b9e9-edf763e17e21");
    h.final(&out);
    return out;
}

test "parse standard uuid with dashes" {
    const u = try Uuid.parse("de53e864-8530-4212-a3d7-c31e60b62e91");
    const want = [_]u8{ 0xde, 0x53, 0xe8, 0x64, 0x85, 0x30, 0x42, 0x12, 0xa3, 0xd7, 0xc3, 0x1e, 0x60, 0xb6, 0x2e, 0x91 };
    try std.testing.expectEqualSlices(u8, want[0..], u.bytes[0..]);
    var buf: [36]u8 = undefined;
    try std.testing.expectEqualStrings("de53e864-8530-4212-a3d7-c31e60b62e91", u.format(buf[0..]));
}

test "parse uuid without dashes" {
    const u = try Uuid.parse("de53e86485304212a3d7c31e60b62e91");
    const with_dash = try Uuid.parse("de53e864-8530-4212-a3d7-c31e60b62e91");
    try std.testing.expect(u.equals(with_dash));
}

test "parse short uuid sha1 path" {
    const a = try Uuid.parse("pb8lpgli");
    const b = try Uuid.parse("pb8lpgli");
    try std.testing.expect(a.equals(b));
    // v5 语义位
    try std.testing.expectEqual(@as(u8, 5 << 4), a.bytes[6] & 0xf0);
    try std.testing.expectEqual(@as(u8, 0x02 << 6), a.bytes[8] & 0xc0);
    // 长度 31 与 0 与 >36 拒绝
    try std.testing.expectError(Uuid.ParseError.InvalidUuid, Uuid.parse("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"));
    try std.testing.expectError(Uuid.ParseError.InvalidUuid, Uuid.parse(""));
    try std.testing.expectError(Uuid.ParseError.InvalidUuid, Uuid.parse("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"));
}

test "cmdkey constant" {
    const u = try Uuid.parse("de53e864-8530-4212-a3d7-c31e60b62e91");
    const ck = cmdKeyOf(u);
    var hexbuf: [32]u8 = undefined;
    _ = std.fmt.bufPrint(&hexbuf, "{s}", .{std.fmt.bytesToHex(ck, .lower)}) catch unreachable;
    try std.testing.expectEqualStrings("d67b69fc215b108c042ab60cf5f01127", hexbuf[0..]);
}
