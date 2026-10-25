//! VMess 编码层（上游 proxy/vmess/encoding/{client,server}.go 服务端方向子集）。
//! M1：请求头明文序列化（向量锚定）+ 响应头 38B 编码/解码（AEAD 双层，
//! 内层明文——M8 互通实测修正：CFB 只用于响应体，头部内层不加密）。
//! M7 补：请求头解密封流程、防重放、分块体读写。

const std = @import("std");
const kdf = @import("../../crypto/kdf.zig");
const aead = @import("aead.zig");
const addr = @import("../../common/addr.zig");
const net = @import("../../common/net.zig");

pub const RequestOption = struct {
    pub const chunk_stream: u8 = 0x01; // 已弃用（legacy），仅识别
    pub const chunk_masking: u8 = 0x04;
    pub const global_padding: u8 = 0x08;
    pub const authenticated_length: u8 = 0x10;
};

pub const SecurityType = enum(u8) {
    auto = 0x00,
    aes128_gcm = 0x03,
    chacha20_poly1305 = 0x04,
    none = 0x05,
    _,

    pub fn fromByte(b: u8) ?SecurityType {
        return switch (b) {
            0x00 => .auto,
            0x03 => .aes128_gcm,
            0x04 => .chacha20_poly1305,
            0x05 => .none,
            else => null,
        };
    }
};

/// parseSecurityType 的枚举名映射（server.go:114-124 + headers.pb.go SecurityType_name）：
/// 字节 0/2 → AUTO（0 经 UNKNOWN→AUTO 兼容改写），3/4 → 具名，其余 → UNKNOWN。
/// DecodeRequestHeader 末检用此名拼 "unknown security type: {name}"。
pub fn securityTypeName(sec: u8) []const u8 {
    return switch (sec) {
        0x00, 0x02 => "AUTO",
        0x03 => "AES128_GCM",
        0x04 => "CHACHA20_POLY1305",
        else => "UNKNOWN",
    };
}

pub const Cmd = struct {
    pub const tcp: u8 = 0x01;
    pub const udp: u8 = 0x02;
    pub const mux: u8 = 0x03;
};

/// 请求头明文序列化（对照 client.go:63-102）。
/// 写入顺序：version(0x01) iv16 key16 resp option (padding<<4|security) reserved command
///           port(BE) address padding random FNV1a(BE)
pub fn encodeRequestHeader(
    out: []u8,
    request_iv: *const [16]u8,
    request_key: *const [16]u8,
    response_header: u8,
    option: u8,
    padding_len: u8,
    security: u8,
    command: u8,
    dest: net.Destination,
    padding_byte: u8,
) usize {
    var w: usize = 0;
    out[w] = 0x01;
    w += 1;
    out[w..][0..16].* = request_iv.*;
    w += 16;
    out[w..][0..16].* = request_key.*;
    w += 16;
    out[w] = response_header;
    w += 1;
    out[w] = option;
    w += 1;
    out[w] = padding_len << 4 | security;
    w += 1;
    out[w] = 0x00; // 保留
    w += 1;
    out[w] = command;
    w += 1;
    // 地址（端口在前）
    if (command != Cmd.mux) {
        w += addr.writePortThenAddress(out[w..], dest);
    }
    // 填充
    var i: usize = 0;
    while (i < padding_len) : (i += 1) out[w + i] = padding_byte;
    w += padding_len;
    // FNV-1a 校验（覆盖之前全部明文）
    const h = std.hash.Fnv1a_32.hash(out[0..w]);
    std.mem.writeInt(u32, out[w..][0..4], h, .big);
    w += 4;
    return w;
}

pub const PlaintextHeader = struct {
    version: u8,
    request_iv: [16]u8,
    request_key: [16]u8,
    response_header: u8,
    option: u8,
    padding_len: u8, // 高 4 位
    security: u8, // 低 4 位
    command: u8,
    dest: ?net.Destination, // Mux 时无地址段 → null
};

/// 请求头明文反序列化（M7 用；先落地便于向量自测与 fuzz）。
/// data 不含 FNV 尾（调用方校验后切片）。
/// 地址解析失败 → error.InvalidAddress（Go：err 被吞、Address 留 nil，末检报
/// "invalid remote address"；这里由 inbound 映射同款文案）。
pub fn decodeRequestHeader(data: []const u8) !PlaintextHeader {
    if (data.len < 41) return error.HeaderTooShort;
    var r: usize = 0;
    var h: PlaintextHeader = undefined;
    h.version = data[r];
    r += 1;
    if (h.version != 0x01) return error.InvalidVersion;
    h.request_iv = data[r..][0..16].*;
    r += 16;
    h.request_key = data[r..][0..16].*;
    r += 16;
    h.response_header = data[r];
    r += 1;
    h.option = data[r];
    r += 1;
    h.padding_len = data[r] >> 4;
    h.security = data[r] & 0x0f;
    r += 1;
    r += 1; // 保留字节
    h.command = data[r];
    r += 1;
    if (h.command == Cmd.mux) {
        h.dest = null;
    } else {
        h.dest = addr.readPortThenAddress(data, &r, null) catch return error.InvalidAddress;
    }
    // 校验 FNV-1a
    if (data.len < r + @as(usize, h.padding_len) + 4) return error.HeaderTooShort;
    const fnv_expect = std.mem.readInt(u32, data[r + @as(usize, h.padding_len) ..][0..4], .big);
    const fnv_got = std.hash.Fnv1a_32.hash(data[0 .. r + @as(usize, h.padding_len)]);
    if (fnv_expect != fnv_got) return error.FnvMismatch;
    return h;
}

/// responseBodyKey/IV = SHA256(requestBodyKey/IV)[:16]
pub fn deriveResponseKeys(resp_key: *[16]u8, resp_iv: *[16]u8, req_key: *const [16]u8, req_iv: *const [16]u8) void {
    var k: [32]u8 = undefined;
    var v: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(req_key, &k, .{});
    std.crypto.hash.sha2.Sha256.hash(req_iv, &v, .{});
    resp_key.* = k[0..16].*;
    resp_iv.* = v[0..16].*;
}

/// 响应头编码（对照 server.go:313-354）。
/// **内层 4 字节是明文**：server.go 把 encryptionWriter 重新指向
/// aeadEncryptedHeaderBuffer（普通 bytes.Buffer），CFB 的 aesStream 只赋给
/// s.responseWriter（响应体）。M8 互通实测修正（此前误做 CFB，Go 客户端
/// 报 "unexpected response header"）。
/// out.len 必须 >= 38。
pub fn encodeResponseHeader(out: []u8, req_key: *const [16]u8, req_iv: *const [16]u8, response_header: u8, option: u8) void {
    var resp_key: [16]u8 = undefined;
    var resp_iv: [16]u8 = undefined;
    deriveResponseKeys(&resp_key, &resp_iv, req_key, req_iv);

    // 内层明文（TCP 时 command 为 nil → MarshalCommand 失败 → 补 {0,0}）
    const inner_plain = [4]u8{ response_header, option, 0x00, 0x00 };

    // 外层长度段（18B）
    var lk: [16]u8 = undefined;
    var ln: [12]u8 = undefined;
    kdf.kdf16(&lk, resp_key[0..], &.{kdf.KDFSaltConstAEADRespHeaderLenKey});
    aead.kdfDerive12(&ln, resp_iv[0..], &.{kdf.KDFSaltConstAEADRespHeaderLenIV});
    var l2: [2]u8 = undefined;
    std.mem.writeInt(u16, &l2, inner_plain.len, .big);
    sys_gcm_encrypt(out[0..18], l2[0..], "", ln, lk);

    // 外层载荷段（20B）：明文内层直接进 AEAD
    var pk: [16]u8 = undefined;
    var pn: [12]u8 = undefined;
    kdf.kdf16(&pk, resp_key[0..], &.{kdf.KDFSaltConstAEADRespHeaderPayloadKey});
    aead.kdfDerive12(&pn, resp_iv[0..], &.{kdf.KDFSaltConstAEADRespHeaderPayloadIV});
    sys_gcm_encrypt(out[18..38], inner_plain[0..], "", pn, pk);
}

/// 响应头解码（自测/互通用；客户端方向逻辑同）：内层即明文
pub fn decodeResponseHeader(wire: *const [38]u8, req_key: *const [16]u8, req_iv: *const [16]u8) ![4]u8 {
    var resp_key: [16]u8 = undefined;
    var resp_iv: [16]u8 = undefined;
    deriveResponseKeys(&resp_key, &resp_iv, req_key, req_iv);

    var lk: [16]u8 = undefined;
    var ln: [12]u8 = undefined;
    kdf.kdf16(&lk, resp_key[0..], &.{kdf.KDFSaltConstAEADRespHeaderLenKey});
    aead.kdfDerive12(&ln, resp_iv[0..], &.{kdf.KDFSaltConstAEADRespHeaderLenIV});
    var l2: [2]u8 = undefined;
    sys_gcm_decrypt(l2[0..], wire[0..18], "", ln, lk) catch return error.AuthFailed;
    const inner_len = std.mem.readInt(u16, &l2, .big);
    if (inner_len != 4) return error.BadInnerLength;

    var pk: [16]u8 = undefined;
    var pn: [12]u8 = undefined;
    kdf.kdf16(&pk, resp_key[0..], &.{kdf.KDFSaltConstAEADRespHeaderPayloadKey});
    aead.kdfDerive12(&pn, resp_iv[0..], &.{kdf.KDFSaltConstAEADRespHeaderPayloadIV});
    var inner: [4]u8 = undefined;
    sys_gcm_decrypt(inner[0..], wire[18..38], "", pn, pk) catch return error.AuthFailed;
    return inner;
}

// AAD 为空（nil）的 GCM 封装
fn sys_gcm_encrypt(out: []u8, m: []const u8, ad: []const u8, npub: [12]u8, key: [16]u8) void {
    var tag: [16]u8 = undefined;
    std.crypto.aead.aes_gcm.Aes128Gcm.encrypt(out[0..m.len], tag[0..], m, ad, npub, key);
    @memcpy(out[m.len..][0..16], tag[0..]);
}

fn sys_gcm_decrypt(out: []u8, block: []const u8, ad: []const u8, npub: [12]u8, key: [16]u8) !void {
    if (block.len < 16) return error.ShortBlock;
    const ct = block[0 .. block.len - 16];
    const tag = block[block.len - 16 ..][0..16].*;
    try std.crypto.aead.aes_gcm.Aes128Gcm.decrypt(out[0..ct.len], ct, tag, ad, npub, key);
}

test "response header encode/decode roundtrip" {
    var req_key: [16]u8 = @splat(0x22);
    var req_iv: [16]u8 = @splat(0x11);
    var wire: [38]u8 = undefined;
    encodeResponseHeader(wire[0..], &req_key, &req_iv, 0x33, 0x04);
    const inner = try decodeResponseHeader(&wire, &req_key, &req_iv);
    try std.testing.expectEqual([4]u8{ 0x33, 0x04, 0x00, 0x00 }, inner);
}
