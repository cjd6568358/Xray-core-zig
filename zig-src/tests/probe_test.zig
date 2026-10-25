//! M0 API 探针：验证本项目依赖的全部 zig 0.17 std API 形状。
//! 任何一个探针编译/断言失败都意味着实现前置假设错误，必须先修。

const std = @import("std");
const xz = @import("../src/main.zig");
const linux = std.os.linux;

test "aes single block (initEnc + encrypt slices)" {
    const aes = std.crypto.core.aes;
    const key: [16]u8 = @splat(0x22);
    var ctx = aes.Aes128.initEnc(key);
    const in: [16]u8 = @splat(0x11);
    var out: [16]u8 = undefined;
    ctx.encrypt(&out, &in);
    // 解密往返
    var dctx = aes.Aes128.initDec(key);
    var back: [16]u8 = undefined;
    dctx.decrypt(&back, &out);
    try std.testing.expectEqualSlices(u8, &in, &back);
}

test "aes128-gcm roundtrip (value key/npub)" {
    const Aes128Gcm = std.crypto.aead.aes_gcm.Aes128Gcm;
    const key: [16]u8 = @splat(0x22);
    const npub: [12]u8 = @splat(0x03);
    const ad = [_]u8{ 0xAA, 0xBB };
    const pt = "hello vmess chunk";
    var ct: [pt.len]u8 = undefined;
    var tag: [16]u8 = undefined;
    Aes128Gcm.encrypt(&ct, &tag, pt, &ad, npub, key);
    var back: [pt.len]u8 = undefined;
    try Aes128Gcm.decrypt(&back, &ct, tag, &ad, npub, key);
    try std.testing.expectEqualStrings(pt, &back);
    // 篡改必须失败
    var bad = ct;
    bad[0] ^= 1;
    try std.testing.expectError(error.AuthenticationFailed, Aes128Gcm.decrypt(&back, &bad, tag, &ad, npub, key));
}

test "chacha20-poly1305 roundtrip" {
    const C = std.crypto.aead.chacha_poly.ChaCha20Poly1305;
    const key: [32]u8 = @splat(0x44);
    const npub: [12]u8 = @splat(0x05);
    var ct: [8]u8 = undefined;
    var tag: [16]u8 = undefined;
    C.encrypt(&ct, &tag, "12345678", "", npub, key);
    var back: [8]u8 = undefined;
    try C.decrypt(&back, &ct, tag, "", npub, key);
    try std.testing.expectEqualStrings("12345678", &back);
}

test "hmac-sha256 / md5 / sha1 / sha256 / shake128" {
    const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;
    var mac: [32]u8 = undefined;
    HmacSha256.create(&mac, "msg", "key");

    var d: [16]u8 = undefined;
    var md5 = std.crypto.hash.Md5.init(.{});
    md5.update("abc");
    md5.final(&d);

    var s1: [20]u8 = undefined;
    var sha1 = std.crypto.hash.Sha1.init(.{});
    sha1.update("abc");
    sha1.final(&s1);

    var s2: [32]u8 = undefined;
    var sha256 = std.crypto.hash.sha2.Sha256.init(.{});
    sha256.update("abc");
    sha256.final(&s2);

    var xof: [8]u8 = undefined;
    var shake = std.crypto.hash.sha3.Shake128.init(.{});
    shake.update("seed");
    shake.squeeze(&xof);
    // 确定性：两次 squeeze 序列一致
    var shake2 = std.crypto.hash.sha3.Shake128.init(.{});
    shake2.update("seed");
    var xof2: [8]u8 = undefined;
    shake2.squeeze(&xof2);
    try std.testing.expectEqualSlices(u8, &xof, &xof2);
}

test "crc32 / fnv1a" {
    const c = std.hash.Crc32.hash("123456789");
    try std.testing.expectEqual(@as(u32, 0xCBF43926), c); // IEEE CRC-32 标准校验值
    const f = std.hash.Fnv1a_32.hash("");
    try std.testing.expectEqual(@as(u32, 0x811C9DC5), f); // FNV-1a 32 offset basis
}

test "json parse ignore_unknown_fields" {
    const Conf = struct {
        name: []const u8,
        port: u16,
        opt: ?bool = null,
    };
    const text = "{\"name\":\"ws\",\"port\":19001,\"futureField\":123}";
    var parsed = try std.json.parseFromSlice(Conf, std.testing.allocator, text, .{ .ignore_unknown_fields = true });
    defer parsed.deinit();
    try std.testing.expectEqualStrings("ws", parsed.value.name);
    try std.testing.expectEqual(@as(u16, 19001), parsed.value.port);
}

test "thread spawn with small stack" {
    const Counter = struct {
        fn run(p: *std.atomic.Value(u32)) void {
            _ = p.fetchAdd(1, .monotonic);
        }
    };
    var c = std.atomic.Value(u32).init(0);
    const t = try std.Thread.spawn(.{ .stack_size = xz.sys.min_thread_stack }, Counter.run, .{&c});
    t.join();
    try std.testing.expectEqual(@as(u32, 1), c.load(.monotonic));
}

test "linux socket syscall + errno" {
    const rc = linux.socket(linux.AF.INET, linux.SOCK.STREAM | linux.SOCK.CLOEXEC, 0);
    try std.testing.expect(linux.errno(rc) == .SUCCESS);
    const fd: xz.sys.Fd = @intCast(rc);
    defer xz.sys.closeFd(fd);
    // setsockopt SO_REUSEADDR（optval/optlen 分参）
    const on: c_int = 1;
    const rc2 = linux.setsockopt(fd, linux.SOL.SOCKET, linux.SO.REUSEADDR, @ptrCast(&on), @sizeOf(c_int));
    try std.testing.expect(linux.errno(rc2) == .SUCCESS);
}

test "sockaddr v4 layout" {
    const sa = xz.sys.SockaddrIn.init(.{ 127, 0, 0, 1 }, 19001);
    try std.testing.expectEqual(@as(u16, linux.AF.INET), sa.family);
    try std.testing.expectEqual(@as(u16, 19001), sa.port());
    // port_be 是字节交换后的值；内存字节序必须是大端 19001 = 0x4A39
    const wire: [2]u8 = @bitCast(sa.port_be);
    try std.testing.expectEqual(@as(u8, @intCast(19001 >> 8)), wire[0]);
    try std.testing.expectEqual(@as(u8, @intCast(19001 & 0xFF)), wire[1]);
    try std.testing.expectEqual(@as(u8, 127), sa.addr[0]);
    try std.testing.expectEqual(@as(usize, 16), @sizeOf(xz.sys.SockaddrIn));
    try std.testing.expectEqual(@as(usize, 28), @sizeOf(xz.sys.SockaddrIn6));
}

test "clock + sleep" {
    const now = xz.sys.nowUnixSecs();
    try std.testing.expect(now > 1700000000);
    const t0 = xz.sys.nowMonoMs();
    xz.sys.sleepMs(5);
    try std.testing.expect(xz.sys.nowMonoMs() >= t0 + 4);
}

test "random fill" {
    var a: [16]u8 = undefined;
    var b: [16]u8 = undefined;
    xz.sys.randomBytes(&a);
    xz.sys.randomBytes(&b);
    try std.testing.expect(!std.mem.eql(u8, &a, &b));
}
