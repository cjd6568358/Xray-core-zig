//! VMess AEAD 头（上游 proxy/vmess/aead/{authid,encrypt}.go 逐语义移植，
//! 与 tools/gen_golden_vectors.go 逐行对应）。
//!
//! 线格式（请求头）：AuthID(16) || 密封长度(18) || connection nonce(8) || 密封载荷(N+16)

const std = @import("std");
const kdf = @import("../../crypto/kdf.zig");
const sys_crypto = std.crypto;

pub const sealed_length_block_len = 18; // 2B 密文 + 16B tag
pub const auth_id_len = 16;
pub const conn_nonce_len = 8;
/// 16(AuthID) + 18(密封长度) + 8(nonce) + 16(空载荷 tag) = 58；总长 = 58 + N
pub const min_header_len = auth_id_len + sealed_length_block_len + conn_nonce_len + 16;

pub const OpenError = error{
    ShortHeader,
    AuthFailed,
    LengthMismatch,
};

/// CreateAuthID：{8B BE(t) + 4B rnd + 4B CRC32(前 12B)} 用 KDF16(cmdKey,"AES Auth ID Encryption") 做 AES-ECB 加密
pub fn createAuthID(out: *[16]u8, cmd_key: *const [16]u8, t: i64, rnd: [4]u8) void {
    var buf: [16]u8 = undefined;
    std.mem.writeInt(u64, buf[0..8], @bitCast(t), .big);
    buf[8..12].* = rnd;
    const zero = std.hash.Crc32.hash(buf[0..12]);
    std.mem.writeInt(u32, buf[12..16], zero, .big);

    var enc_key: [16]u8 = undefined;
    kdf.kdf16(&enc_key, cmd_key, &.{kdf.KDFSaltConstAuthIDEncryptionKey});
    const ctx = sys_crypto.core.aes.Aes128.initEnc(enc_key);
    ctx.encrypt(out, &buf);
}

/// AuthID 解密校验（服务端逐用户定位用）：解 ECB 后校验 CRC32
pub fn verifyAuthID(cmd_key: *const [16]u8, auth_id: *const [16]u8) bool {
    var enc_key: [16]u8 = undefined;
    kdf.kdf16(&enc_key, cmd_key, &.{kdf.KDFSaltConstAuthIDEncryptionKey});
    const ctx = sys_crypto.core.aes.Aes128.initDec(enc_key);
    var plain: [16]u8 = undefined;
    ctx.decrypt(&plain, auth_id);
    const crc = std.hash.Crc32.hash(plain[0..12]);
    const stored = std.mem.readInt(u32, plain[12..16], .big);
    return stored == crc;
}

/// SealVMessAEADHeader：完整密封（out.len == min_header_len + data.len）
pub fn sealHeader(out: []u8, cmd_key: *const [16]u8, data: []const u8, t: i64, rnd: [4]u8, conn_nonce: *const [8]u8) void {
    std.debug.assert(out.len == min_header_len + data.len);

    var auth_id: [16]u8 = undefined;
    createAuthID(&auth_id, cmd_key, t, rnd);

    // 长度段
    {
        var lk: [16]u8 = undefined;
        var ln: [12]u8 = undefined;
        kdf.kdf16(&lk, cmd_key, &.{ kdf.KDFSaltConstVMessHeaderPayloadLengthAEADKey, auth_id[0..], conn_nonce });
        kdfDerive12(&ln, cmd_key, &.{ kdf.KDFSaltConstVMessHeaderPayloadLengthAEADIV, auth_id[0..], conn_nonce });
        var l2: [2]u8 = undefined;
        std.mem.writeInt(u16, &l2, @intCast(data.len), .big);
        var sealed_len: [sealed_length_block_len]u8 = undefined;
        sys_crypto.aead.aes_gcm.Aes128Gcm.encrypt(sealed_len[0..2], sealed_len[2..18], l2[0..], auth_id[0..], ln, lk);
        @memcpy(out[0..16], &auth_id);
        @memcpy(out[16..34], &sealed_len);
        @memcpy(out[34..42], conn_nonce);
    }
    // 载荷段
    {
        var pk: [16]u8 = undefined;
        var pn: [12]u8 = undefined;
        kdf.kdf16(&pk, cmd_key, &.{ kdf.KDFSaltConstVMessHeaderPayloadAEADKey, auth_id[0..], conn_nonce });
        kdfDerive12(&pn, cmd_key, &.{ kdf.KDFSaltConstVMessHeaderPayloadAEADIV, auth_id[0..], conn_nonce });
        const pay = out[42..];
        sys_crypto.aead.aes_gcm.Aes128Gcm.encrypt(pay[0..data.len], pay[data.len..][0..16], data, auth_id[0..], pn, pk);
    }
}

/// OpenVMessAEADHeader 第一步：解 18B 密封长度（payload 为 AuthID 之后的完整剩余）
pub fn openHeaderLength(payload: []const u8, cmd_key: *const [16]u8, auth_id: *const [16]u8) OpenError!u16 {
    if (payload.len < sealed_length_block_len + conn_nonce_len) return OpenError.ShortHeader;
    const enc_len = payload[0..sealed_length_block_len];
    const nonce = payload[sealed_length_block_len..][0..conn_nonce_len];

    var lk: [16]u8 = undefined;
    var ln: [12]u8 = undefined;
    kdf.kdf16(&lk, cmd_key, &.{ kdf.KDFSaltConstVMessHeaderPayloadLengthAEADKey, auth_id, nonce });
    kdfDerive12(&ln, cmd_key, &.{ kdf.KDFSaltConstVMessHeaderPayloadLengthAEADIV, auth_id, nonce });
    var l2: [2]u8 = undefined;
    sys_crypto.aead.aes_gcm.Aes128Gcm.decrypt(l2[0..], enc_len[0..2], enc_len[2..18].*, auth_id, ln, lk) catch return OpenError.AuthFailed;
    return std.mem.readInt(u16, &l2, .big);
}

/// OpenVMessAEADHeader 第二步：解密封载荷（out.len >= payload_len）
pub fn openHeaderPayload(out: []u8, payload: []const u8, cmd_key: *const [16]u8, auth_id: *const [16]u8) OpenError!usize {
    const nonce = payload[sealed_length_block_len..][0..conn_nonce_len];
    const enc_pay = payload[sealed_length_block_len + conn_nonce_len ..];
    if (enc_pay.len < 16) return OpenError.ShortHeader;
    const ct = enc_pay[0 .. enc_pay.len - 16];
    const tag = enc_pay[enc_pay.len - 16 ..][0..16].*;

    var pk: [16]u8 = undefined;
    var pn: [12]u8 = undefined;
    kdf.kdf16(&pk, cmd_key, &.{ kdf.KDFSaltConstVMessHeaderPayloadAEADKey, auth_id, nonce });
    kdfDerive12(&pn, cmd_key, &.{ kdf.KDFSaltConstVMessHeaderPayloadAEADIV, auth_id, nonce });
    sys_crypto.aead.aes_gcm.Aes128Gcm.decrypt(out[0..ct.len], ct, tag, auth_id, pn, pk) catch return OpenError.AuthFailed;
    return ct.len;
}

/// KDF 取 [0..12]（nonce 派生）
pub fn kdfDerive12(out: *[12]u8, key: []const u8, path: []const []const u8) void {
    var full: [32]u8 = undefined;
    kdf.kdf(&full, key, path);
    @memcpy(out, full[0..12]);
}

test "authid verify roundtrip" {
    var cmd_key: [16]u8 = @splat(0xAB);
    var auth_id: [16]u8 = undefined;
    createAuthID(&auth_id, &cmd_key, 1700000000, .{ 0x11, 0x22, 0x33, 0x44 });
    try std.testing.expect(verifyAuthID(&cmd_key, &auth_id));
    var bad = auth_id;
    bad[0] ^= 1;
    try std.testing.expect(!verifyAuthID(&cmd_key, &bad));
}

test "seal/open header roundtrip + tamper" {
    var cmd_key: [16]u8 = @splat(0xCD);
    const data = "payload-header-bytes-0123456789";
    var out: [min_header_len + data.len]u8 = undefined;
    sealHeader(out[0..], &cmd_key, data, 1700000000, .{ 1, 2, 3, 4 }, &([8]u8{ 1, 2, 3, 4, 5, 6, 7, 8 }));

    const auth_id = out[0..16].*;
    const rest = out[16..];
    const n = try openHeaderLength(rest, &cmd_key, &auth_id);
    try std.testing.expectEqual(@as(u16, data.len), n);
    var plain: [64]u8 = undefined;
    const got = try openHeaderPayload(plain[0..], rest, &cmd_key, &auth_id);
    try std.testing.expectEqualStrings(data, plain[0..got]);

    // 篡改长度段必须失败；载荷篡改走载荷 GCM 失败路径
    var bad = out;
    bad[20] ^= 1; // 长度段 [16..34) 内的密文字节
    var bad_auth = bad[0..16].*;
    var bad_rest = bad[16..];
    try std.testing.expectError(OpenError.AuthFailed, openHeaderLength(bad_rest, &cmd_key, &bad_auth));

    bad = out;
    bad[50] ^= 1; // 载荷区密文字节：长度段可开（AAD 仅覆盖 AuthID），载荷 GCM 必须失败
    bad_auth = bad[0..16].*;
    bad_rest = bad[16..];
    const n2 = try openHeaderLength(bad_rest, &cmd_key, &bad_auth);
    try std.testing.expectEqual(@as(u16, data.len), n2);
    var back2: [64]u8 = undefined;
    try std.testing.expectError(OpenError.AuthFailed, openHeaderPayload(back2[0..], bad_rest, &cmd_key, &bad_auth));
}
