//! VMess AEAD KDF（上游 proxy/vmess/aead/kdf.go 的逐语义移植）。
//!
//! 上游用 Go 闭包把"前一层 HMAC 对象"当作后一层 HMAC 的内层哈希复用
//! （hash2 包装绕过唯一性检查）。go1.24+（FIPS hmac）语义已用插桩复刻在
//! 打包机上验证并锁定到黄金向量（tests/golden/vmess_aead.txt，8 组 KDF
//! 全部逐字节命中）。关键行为：
//!   1. hmac.New(h, key)：h() 调两次（outer 先、inner 后），本构造两次都
//!      返回同一个前层节点（hash2 包装对外透明）；
//!   2. Sum()：mid = inner.sum()；outer.resetFull()（别名会连锁重置前层）；
//!      outer.write(self.opad)（opad 作为数据流入前层 inner）；outer.write(mid)；
//!      结果 = outer.sum()；
//!   3. sha256.Sum 非变异（副本求值）。
//! 禁止"等价改写"：任何简化必须先过黄金向量。

const std = @import("std");
const Sha256 = std.crypto.hash.sha2.Sha256;

// ==== 上游 aead/consts.go 全部盐常量 ====
pub const KDFSaltConstAuthIDEncryptionKey = "AES Auth ID Encryption";
pub const KDFSaltConstAEADRespHeaderLenKey = "AEAD Resp Header Len Key";
pub const KDFSaltConstAEADRespHeaderLenIV = "AEAD Resp Header Len IV";
pub const KDFSaltConstAEADRespHeaderPayloadKey = "AEAD Resp Header Key";
pub const KDFSaltConstAEADRespHeaderPayloadIV = "AEAD Resp Header IV";
pub const KDFSaltConstVMessAEADKDF = "VMess AEAD KDF";
pub const KDFSaltConstVMessHeaderPayloadAEADKey = "VMess Header AEAD Key";
pub const KDFSaltConstVMessHeaderPayloadAEADIV = "VMess Header AEAD Nonce";
pub const KDFSaltConstVMessHeaderPayloadLengthAEADKey = "VMess Header AEAD Key_Length";
pub const KDFSaltConstVMessHeaderPayloadLengthAEADIV = "VMess Header AEAD Nonce_Length";
pub const KDFSaltConstAuthLengthEn = "auth_len";

/// KDF 链最大深度：H0 + path 元素。协议内最长路径 3 元素，留裕量。
pub const max_kdf_depth = 7;

pub const HashRef = union(enum) {
    sha: *Sha256,
    hmac: *GoHmac,

    pub fn write(self: HashRef, data: []const u8) void {
        switch (self) {
            .sha => |s| s.update(data),
            .hmac => |h| h.write(data),
        }
    }

    pub fn resetFull(self: HashRef) void {
        switch (self) {
            .sha => |s| s.* = Sha256.init(.{}),
            .hmac => |h| h.resetFull(),
        }
    }

    /// 非变异求值（Go hash.Sum 语义）：副本 finalize
    pub fn sum(self: HashRef, out: *[32]u8) void {
        switch (self) {
            .sha => |s| {
                var cp = s.*;
                cp.final(out);
            },
            .hmac => |h| h.sum(out),
        }
    }
};

pub const GoHmac = struct {
    outer: HashRef,
    inner: HashRef,
    ipad: [64]u8 = undefined,
    opad: [64]u8 = undefined,

    /// 就地构造（self 必须在池内不再移动，内部持有 self 引用）
    pub fn initInPlace(self: *GoHmac, outer: HashRef, inner: HashRef, key: []const u8) void {
        self.outer = outer;
        self.inner = inner;
        var key_digest: [32]u8 = undefined;
        var effective = key;
        if (key.len > 64) {
            // Go: hm.outer.Write(key); key = hm.outer.Sum(nil)
            self.outer.write(key);
            self.outer.sum(&key_digest);
            effective = key_digest[0..];
        }
        var i: usize = 0;
        while (i < 64) : (i += 1) {
            const kb: u8 = if (i < effective.len) effective[i] else 0;
            self.ipad[i] = kb ^ 0x36;
            self.opad[i] = kb ^ 0x5c;
        }
        self.inner.write(self.ipad[0..]);
    }

    pub fn write(self: *GoHmac, data: []const u8) void {
        self.inner.write(data);
    }

    pub fn sum(self: *GoHmac, out: *[32]u8) void {
        var mid: [32]u8 = undefined;
        self.inner.sum(&mid);
        self.outer.resetFull();
        self.outer.write(self.opad[0..]);
        self.outer.write(mid[0..]);
        self.outer.sum(out);
    }

    pub fn resetFull(self: *GoHmac) void {
        self.inner.resetFull();
        self.inner.write(self.ipad[0..]);
    }
};

/// 上游 KDF(key, path...)。out 收 32 字节。
pub fn kdf(out: *[32]u8, key: []const u8, path: []const []const u8) void {
    std.debug.assert(path.len + 1 <= max_kdf_depth);
    var shas: [2]Sha256 = undefined;
    var nodes: [max_kdf_depth]GoHmac = undefined;

    shas[0] = Sha256.init(.{});
    shas[1] = Sha256.init(.{});
    nodes[0].initInPlace(.{ .sha = &shas[0] }, .{ .sha = &shas[1] }, KDFSaltConstVMessAEADKDF);
    var cur: *GoHmac = &nodes[0];
    for (path, 0..) |v, i| {
        // 闭包两次调用都返回当前节点（hash2 包装对外透明）
        nodes[i + 1].initInPlace(.{ .hmac = cur }, .{ .hmac = cur }, v);
        cur = &nodes[i + 1];
    }
    cur.write(key);
    cur.sum(out);
}

/// KDF16 = KDF(...)[:16]
pub fn kdf16(out: *[16]u8, key: []const u8, path: []const []const u8) void {
    var full: [32]u8 = undefined;
    kdf(&full, key, path);
    @memcpy(out, full[0..16]);
}

test "kdf basic determinism" {
    var a: [32]u8 = undefined;
    var b: [32]u8 = undefined;
    kdf(&a, "key", &.{"path"});
    kdf(&b, "key", &.{"path"});
    try std.testing.expectEqualSlices(u8, &a, &b);
    // 不同 path 顺序结果不同
    kdf(&b, "key", &.{ "b", "a" });
    try std.testing.expect(!std.mem.eql(u8, &a, &b));
}
