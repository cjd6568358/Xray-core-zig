//! ChaCha20-Poly1305 密钥派生 + SHAKE128 分块尺寸解析器
//! （上游 proxy/vmess/encoding/auth.go 逐语义移植）。

const std = @import("std");
const Shake128 = std.crypto.hash.sha3.Shake128;

/// GenerateChacha20Poly1305Key：key32 = MD5(key16) || MD5(MD5(key16))
pub fn generateChacha20Poly1305Key(out: *[32]u8, key: []const u8) void {
    std.crypto.hash.Md5.hash(key, out[0..16], .{});
    std.crypto.hash.Md5.hash(out[0..16], out[16..32], .{});
}

/// ShakeSizeParser：SHAKE128(种子=方向 bodyIV) 流式取 2B 掩码
pub const ShakeSizeParser = struct {
    shake: Shake128,

    pub const size_bytes = 2;
    pub const max_padding_len: u16 = 64;

    pub fn init(nonce: []const u8) ShakeSizeParser {
        var s = ShakeSizeParser{ .shake = Shake128.init(.{}) };
        s.shake.update(nonce);
        return s;
    }

    fn next(self: *ShakeSizeParser) u16 {
        var buf: [2]u8 = undefined;
        self.shake.squeeze(&buf);
        return std.mem.readInt(u16, &buf, .big);
    }

    /// 解码线上长度段（异或掩码）
    pub fn decode(self: *ShakeSizeParser, wire: *const [2]u8) u16 {
        const mask = self.next();
        const size = std.mem.readInt(u16, wire, .big);
        return mask ^ size;
    }

    /// 编码线上长度段
    pub fn encode(self: *ShakeSizeParser, size: u16, wire: *[2]u8) void {
        const mask = self.next();
        std.mem.writeInt(u16, wire, mask ^ size, .big);
    }

    pub fn nextPaddingLen(self: *ShakeSizeParser) u16 {
        return self.next() % 64;
    }
};

test "chacha key derivation shape" {
    var key: [32]u8 = undefined;
    var src: [16]u8 = @splat(0x22);
    generateChacha20Poly1305Key(&key, src[0..]);
    // 前 16B = MD5(0x22*16)
    var t: [16]u8 = undefined;
    std.crypto.hash.Md5.hash(src[0..], t[0..], .{});
    try std.testing.expectEqualSlices(u8, &t, key[0..16]);
    var t2: [16]u8 = undefined;
    std.crypto.hash.Md5.hash(t[0..], t2[0..], .{});
    try std.testing.expectEqualSlices(u8, &t2, key[16..32]);
}

test "shake size parser encode/decode roundtrip + padding range" {
    const nonce = [16]u8{ 0x11, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
    var sp = ShakeSizeParser.init(nonce[0..]);
    var wire: [2]u8 = undefined;
    sp.encode(1234, &wire);
    var sp2 = ShakeSizeParser.init(nonce[0..]);
    try std.testing.expectEqual(@as(u16, 1234), sp2.decode(&wire));
    var i: usize = 0;
    while (i < 100) : (i += 1) {
        try std.testing.expect(sp.nextPaddingLen() < 64);
    }
}
