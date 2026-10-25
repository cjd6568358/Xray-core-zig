//! AES-128-CFB（Go crypto/cipher/cfb.go 逐语义移植）。
//!
//! 上游用法只有 VMess 响应头内层：单次 4 字节（< 1 block）。本实现仍按
//! Go 的字节级寄存器语义完整实现（refill 时 out=E(next); next=out; 字节级
//! 反馈写入 next[outUsed]），保证任何长度下与 Go 逐字节一致。
//! zig 0.17 std.crypto 无 CFB 模式，手写（设计文档 §2.4 预期内）。

const std = @import("std");
const aes = std.crypto.core.aes;

pub const Cfb = struct {
    enc_ctx: aes.AesEncryptCtx(aes.Aes128),
    next: [16]u8,
    out: [16]u8,
    out_used: usize,
    decrypt: bool,

    /// Go NewCFBEncrypter：反馈取密文
    pub fn initEncryptor(key: [16]u8, iv: [16]u8) Cfb {
        return .{
            .enc_ctx = aes.Aes128.initEnc(key),
            .next = iv,
            .out = undefined,
            .out_used = 16, // 触发首次 refill
            .decrypt = false,
        };
    }

    /// Go NewCFBDecrypter：反馈取密文（src）
    pub fn initDecryptor(key: [16]u8, iv: [16]u8) Cfb {
        var c = initEncryptor(key, iv);
        c.decrypt = true;
        return c;
    }

    fn refill(x: *Cfb) void {
        if (x.out_used == x.out.len) {
            x.enc_ctx.encrypt(x.out[0..], x.next[0..]);
            x.next = x.out;
            x.out_used = 0;
        }
    }

    /// Go (*cfb).XORKeyStream：dst.len >= src.len
    pub fn xorKeyStream(x: *Cfb, dst: []u8, src: []const u8) void {
        std.debug.assert(dst.len >= src.len);
        var di: usize = 0;
        while (di < src.len) {
            x.refill();
            while (x.out_used < 16 and di < src.len) {
                const ks = x.out[x.out_used];
                if (x.decrypt) {
                    const c = src[di];
                    dst[di] = c ^ ks;
                    x.next[x.out_used] = c;
                } else {
                    dst[di] = src[di] ^ ks;
                    x.next[x.out_used] = dst[di];
                }
                x.out_used += 1;
                di += 1;
            }
        }
    }
};

test "cfb roundtrip multi-block + partial" {
    const key: [16]u8 = @splat(0x11);
    const iv: [16]u8 = @splat(0x22);
    const pt = "The quick brown fox jumps over the lazy dog!"; // 45 字节（跨块+尾块）
    var ct: [pt.len]u8 = undefined;
    var enc = Cfb.initEncryptor(key, iv);
    enc.xorKeyStream(ct[0..], pt);
    var back: [pt.len]u8 = undefined;
    var dec = Cfb.initDecryptor(key, iv);
    dec.xorKeyStream(back[0..], ct[0..]);
    try std.testing.expectEqualStrings(pt, back[0..]);
}

test "cfb single partial block == ECB(IV) xor" {
    // 首块且长度 < 16：密文 = 明文 ^ E(IV)（寄存器尚无反馈）
    const key: [16]u8 = @splat(0x33);
    const iv: [16]u8 = @splat(0x44);
    const pt = [4]u8{ 0x33, 0x04, 0x00, 0x00 };
    var ct: [4]u8 = undefined;
    var enc = Cfb.initEncryptor(key, iv);
    enc.xorKeyStream(ct[0..], pt[0..]);
    var ks: [16]u8 = undefined;
    std.crypto.core.aes.Aes128.initEnc(key).encrypt(ks[0..], iv[0..]);
    for (pt, 0..) |p, i| try std.testing.expectEqual(p ^ ks[i], ct[i]);
}
