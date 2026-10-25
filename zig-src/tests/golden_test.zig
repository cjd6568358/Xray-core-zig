//! 黄金向量测试（zig-src/tests/golden/vmess_aead.txt）——密码层硬验收。
//! 逐字节比对：8 组 KDF、AuthID、密封请求头 124B、响应头 38B、VLESS 头。

const std = @import("std");
const xz = @import("../src/main.zig");

const golden_text = @embedFile("golden/vmess_aead.txt");

/// 取向量值（行首精确匹配 KEY+空格）
fn vec(name: []const u8) ?[]const u8 {
    var lines = std.mem.splitScalar(u8, golden_text, '\n');
    while (lines.next()) |line_raw| {
        const line = std.mem.trim(u8, line_raw, " \r\t");
        if (line.len == 0 or line[0] == '#') continue;
        const sp = std.mem.indexOfScalar(u8, line, ' ') orelse continue;
        if (std.mem.eql(u8, line[0..sp], name)) {
            return std.mem.trim(u8, line[sp + 1 ..], " \r\t");
        }
    }
    return null;
}

fn hexBytes(alloc: std.mem.Allocator, name: []const u8) ![]u8 {
    const v = vec(name) orelse return error.VectorMissing;
    return std.fmt.allocPrint(alloc, "{s}", .{v}) catch return error.OutOfMemory;
}

fn expectHex(name: []const u8, got: []const u8) !void {
    const want = vec(name) orelse return error.VectorMissing;
    var buf: [512]u8 = undefined;
    const hexdig = "0123456789abcdef";
    const n = @min(got.len, buf.len / 2);
    for (0..n) |i| {
        buf[i * 2] = hexdig[got[i] >> 4];
        buf[i * 2 + 1] = hexdig[got[i] & 0x0f];
    }
    if (!std.mem.eql(u8, buf[0..want.len], want)) {
        std.debug.print("VECTOR MISMATCH {s}\n  got : {s}\n  want: {s}\n", .{ name, buf[0 .. n * 2], want });
        return error.VectorMismatch;
    }
}

fn fixedInputs() struct {
    uuid_bytes: [16]u8,
    cmd_key: [16]u8,
    t: i64,
    rnd: [4]u8,
    nonce: [8]u8,
    req_iv: [16]u8,
    req_key: [16]u8,
} {
    var u = xz.uuid.Uuid.parse("de53e864-8530-4212-a3d7-c31e60b62e91") catch unreachable;
    _ = &u;
    const req_iv: [16]u8 = @splat(0x11);
    const req_key: [16]u8 = @splat(0x22);
    return .{
        .uuid_bytes = u.bytes,
        .cmd_key = xz.uuid.cmdKeyOf(u),
        .t = 1700000000,
        .rnd = .{ 0x11, 0x22, 0x33, 0x44 },
        .nonce = .{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 },
        .req_iv = req_iv,
        .req_key = req_key,
    };
}

test "golden: cmd key" {
    const fi = fixedInputs();
    try expectHex("CMD_KEY", fi.cmd_key[0..]);
}

test "golden: auth id" {
    const fi = fixedInputs();
    var auth_id: [16]u8 = undefined;
    xz.vmess_aead.createAuthID(&auth_id, &fi.cmd_key, fi.t, fi.rnd);
    try expectHex("AUTH_ID", auth_id[0..]);
}

test "golden: kdf auth id key" {
    const fi = fixedInputs();
    var k: [16]u8 = undefined;
    xz.kdf.kdf16(&k, fi.cmd_key[0..], &.{xz.kdf.KDFSaltConstAuthIDEncryptionKey});
    try expectHex("KDF16_AUTH_ID_KEY", k[0..]);
}

test "golden: kdf header len key/nonce" {
    const fi = fixedInputs();
    var auth_id: [16]u8 = undefined;
    xz.vmess_aead.createAuthID(&auth_id, &fi.cmd_key, fi.t, fi.rnd);

    var k16: [16]u8 = undefined;
    xz.kdf.kdf16(&k16, fi.cmd_key[0..], &.{ xz.kdf.KDFSaltConstVMessHeaderPayloadLengthAEADKey, auth_id[0..], fi.nonce[0..] });
    try expectHex("KDF16_HDR_LEN_KEY", k16[0..]);

    var n12: [12]u8 = undefined;
    xz.vmess_aead.kdfDerive12(&n12, fi.cmd_key[0..], &.{ xz.kdf.KDFSaltConstVMessHeaderPayloadLengthAEADIV, auth_id[0..], fi.nonce[0..] });
    try expectHex("KDF12_HDR_LEN_NONCE", n12[0..]);

    xz.kdf.kdf16(&k16, fi.cmd_key[0..], &.{ xz.kdf.KDFSaltConstVMessHeaderPayloadAEADKey, auth_id[0..], fi.nonce[0..] });
    try expectHex("KDF16_HDR_PAY_KEY", k16[0..]);

    xz.vmess_aead.kdfDerive12(&n12, fi.cmd_key[0..], &.{ xz.kdf.KDFSaltConstVMessHeaderPayloadAEADIV, auth_id[0..], fi.nonce[0..] });
    try expectHex("KDF12_HDR_PAY_NONCE", n12[0..]);
}

test "golden: request header plain + sealed + open roundtrip" {
    const fi = fixedInputs();
    var plain: [128]u8 = undefined;
    const plain_len = xz.vmess_encoding.encodeRequestHeader(
        plain[0..],
        &fi.req_iv,
        &fi.req_key,
        0x33,
        xz.vmess_encoding.RequestOption.chunk_masking,
        5,
        3, // AES128_GCM
        0x01, // TCP
        .{ .network = .tcp, .address = .{ .domain = "www.example.com" }, .port = 443 },
        0xAA,
    );
    try std.testing.expectEqual(@as(u16, 66), std.fmt.parseInt(u16, vec("REQ_HEADER_PLAIN_LEN") orelse "0", 10) catch 0);
    try expectHex("REQ_HEADER_PLAIN", plain[0..plain_len]);

    var sealed: [128]u8 = undefined;
    xz.vmess_aead.sealHeader(sealed[0 .. plain_len + 58], &fi.cmd_key, plain[0..plain_len], fi.t, fi.rnd, &fi.nonce);
    const sealed_len: usize = plain_len + 58;
    try std.testing.expectEqual(@as(u16, 124), std.fmt.parseInt(u16, vec("REQ_HEADER_SEALED_LEN") orelse "0", 10) catch 0);
    try expectHex("REQ_HEADER_SEALED", sealed[0..sealed_len]);

    // open 往返
    const auth_id = sealed[0..16].*;
    const rest = sealed[16..sealed_len];
    const n = try xz.vmess_aead.openHeaderLength(rest, &fi.cmd_key, &auth_id);
    try std.testing.expectEqual(@as(u16, @intCast(plain_len)), n);
    var back: [128]u8 = undefined;
    const got = try xz.vmess_aead.openHeaderPayload(back[0..], rest, &fi.cmd_key, &auth_id);
    try std.testing.expectEqualSlices(u8, plain[0..plain_len], back[0..got]);

    // 篡改必须失败（与上游 TestOpenVMessAEADHeader2 同型）：前 42B（AuthID+长度段+nonce）逐字节翻转必须全拒；
    // 载荷区（42..60）翻转不影响长度段（AAD 仅覆盖 AuthID），但载荷 GCM 必须失败。
    var corrupted: [128]u8 = sealed;
    var byte_i: usize = 0;
    while (byte_i < 60) : (byte_i += 1) {
        corrupted[byte_i] ^= 0x01;
        const bad_auth = corrupted[0..16].*;
        const bad_rest = corrupted[16..];
        if (byte_i < 42) {
            try std.testing.expectError(xz.vmess_aead.OpenError.AuthFailed, xz.vmess_aead.openHeaderLength(bad_rest, &fi.cmd_key, &bad_auth));
        } else {
            const n2 = try xz.vmess_aead.openHeaderLength(bad_rest, &fi.cmd_key, &bad_auth);
            try std.testing.expectEqual(@as(u16, @intCast(plain_len)), n2);
            var back2: [128]u8 = undefined;
            try std.testing.expectError(xz.vmess_aead.OpenError.AuthFailed, xz.vmess_aead.openHeaderPayload(back2[0..], bad_rest, &fi.cmd_key, &bad_auth));
        }
        corrupted[byte_i] ^= 0x01;
    }
}

test "golden: response header keys and wire" {
    const fi = fixedInputs();
    var resp_key: [16]u8 = undefined;
    var resp_iv: [16]u8 = undefined;
    xz.vmess_encoding.deriveResponseKeys(&resp_key, &resp_iv, &fi.req_key, &fi.req_iv);
    try expectHex("RESP_BODY_KEY", resp_key[0..]);
    try expectHex("RESP_BODY_IV", resp_iv[0..]);

    var k16: [16]u8 = undefined;
    var n12: [12]u8 = undefined;
    xz.kdf.kdf16(&k16, resp_key[0..], &.{xz.kdf.KDFSaltConstAEADRespHeaderLenKey});
    try expectHex("KDF16_RESP_LEN_KEY", k16[0..]);
    xz.vmess_aead.kdfDerive12(&n12, resp_iv[0..], &.{xz.kdf.KDFSaltConstAEADRespHeaderLenIV});
    try expectHex("KDF12_RESP_LEN_IV", n12[0..]);
    xz.kdf.kdf16(&k16, resp_key[0..], &.{xz.kdf.KDFSaltConstAEADRespHeaderPayloadKey});
    try expectHex("KDF16_RESP_PAY_KEY", k16[0..]);
    xz.vmess_aead.kdfDerive12(&n12, resp_iv[0..], &.{xz.kdf.KDFSaltConstAEADRespHeaderPayloadIV});
    try expectHex("KDF12_RESP_PAY_IV", n12[0..]);

    var wire: [38]u8 = undefined;
    xz.vmess_encoding.encodeResponseHeader(wire[0..], &fi.req_key, &fi.req_iv, 0x33, 0x04);
    try expectHex("RESP_HEADER_WIRE", wire[0..]);

    const inner = try xz.vmess_encoding.decodeResponseHeader(&wire, &fi.req_key, &fi.req_iv);
    try std.testing.expectEqual([4]u8{ 0x33, 0x04, 0x00, 0x00 }, inner);
}

test "golden: gcm seal isolation (hardcoded keys)" {
    // 定位用：绕过 kdf/cfb，直接用向量中的密钥封 2 字节长度段
    var lk: [16]u8 = undefined;
    _ = std.fmt.hexToBytes(lk[0..], "afbae8db4c772a23489bf2e071f511db") catch unreachable;
    var ln: [12]u8 = undefined;
    _ = std.fmt.hexToBytes(ln[0..], "7ed17fe137bae18130cab191") catch unreachable;
    var l2: [2]u8 = undefined;
    std.mem.writeInt(u16, &l2, 4, .big);
    var block: [18]u8 = undefined;
    var tag: [16]u8 = undefined;
    std.crypto.aead.aes_gcm.Aes128Gcm.encrypt(block[0..2], tag[0..], l2[0..], "", ln, lk);
    @memcpy(block[2..18], tag[0..]);
    const expected = [18]u8{
        0x33, 0x9e, 0xf2, 0x72, 0x97, 0x42, 0xf3, 0x06, 0xdc, 0x36, 0x16, 0x52, 0x19, 0xd7, 0xdf, 0x25,
        0xd4, 0x23,
    };
    if (!std.mem.eql(u8, block[0..18], expected[0..])) {
        std.debug.print("GCM isolation got: {x}\n", .{block[0..18]});
        return error.VectorMismatch;
    }
}

test "golden: vless request header" {
    const fi = fixedInputs();
    const u = xz.uuid.Uuid{ .bytes = fi.uuid_bytes };
    var buf: [64]u8 = undefined;
    const n = xz.vless_encoding.encodeRequestHeader(buf[0..], u, xz.vless_encoding.Command.tcp, .{
        .network = .tcp,
        .address = .{ .domain = "www.example.com" },
        .port = 443,
    });
    try expectHex("VLESS_REQ_HEADER", buf[0..n]);
}
