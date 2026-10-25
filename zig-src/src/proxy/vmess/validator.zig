//! VMess 用户定位（对照 proxy/vmess/aead/authid.go AuthIDDecoderHolder +
//! common/protocol TimeedUserValidator 的 AEAD 路径 @ v26.10.21）。
//!
//! Match：逐用户 AES-ECB 解密 AuthID（KDF16(cmdKey,"AES Auth ID Encryption")）→
//! CRC32(前 12B) 校验 → 命中者**中止遍历**做时间/防重放检查（Go 同：crc 命中后
//! 直接 return 错误，不再尝试其他用户）→ t<0 → NegativeTime；|abs(t)-now| > 120s →
//! InvalidTime；ReplayFilter 拒 → Replay。

const std = @import("std");
const sys = @import("../../common/sys.zig");
const kdf = @import("../../crypto/kdf.zig");
const conf_vmess = @import("../../conf/vmess.zig");
const replay = @import("replay.zig");

pub const MatchError = error{
    NotFound, // user do not exist
    NegativeTime, // timestamp is negative
    InvalidTime, // invalid timestamp, perhaps unsynchronized time
    Replay, // replayed request
    OutOfMemory,
};

pub const Validator = struct {
    users: []const conf_vmess.VmessClient.Built,
    filter: *replay.ReplayFilter,

    /// GetAEAD 路径：AuthID → 用户（成功即通过防重放登记）
    pub fn match(self: *Validator, auth_id: *const [16]u8, now_s: i64) MatchError!*const conf_vmess.VmessClient.Built {
        for (self.users) |*u| {
            var enc_key: [16]u8 = undefined;
            kdf.kdf16(&enc_key, &u.cmd_key, &.{kdf.KDFSaltConstAuthIDEncryptionKey});
            const ctx = std.crypto.core.aes.Aes128.initDec(enc_key);
            var plain: [16]u8 = undefined;
            ctx.decrypt(&plain, auth_id);

            const stored_crc = std.mem.readInt(u32, plain[12..16], .big);
            if (stored_crc != std.hash.Crc32.hash(plain[0..12])) continue; // 非本用户

            const t: i64 = @bitCast(std.mem.readInt(u64, plain[0..8], .big));
            if (t < 0) return MatchError.NegativeTime;

            const diff = @abs(@abs(@as(f64, @floatFromInt(t))) - @as(f64, @floatFromInt(now_s)));
            if (diff > 120.0) return MatchError.InvalidTime;

            if (!self.filter.check(auth_id)) return MatchError.Replay;
            return u;
        }
        return MatchError.NotFound;
    }
};

// ============================ 测试 ============================

const test_uuid_str = "de53e864-8530-4212-a3d7-c31e60b62e91";

test "validator：时间窗内命中 + 窗外拒绝 + 防重放拒绝" {
    const a = std.testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(a);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const cfg = conf_vmess.VmessInboundConfig{
        .clients = &.{.{ .id = test_uuid_str, .email = "pb8lpgli" }},
    };
    const built = try cfg.build(arena);

    const filter = try replay.ReplayFilter.create(a);
    defer filter.destroy();
    var v = Validator{ .users = built.users, .filter = filter };

    const vmess_aead = @import("aead.zig");
    const now = sys.nowUnixSecs();

    // 生成合法 AuthID（客户端侧）
    var auth_id: [16]u8 = undefined;
    vmess_aead.createAuthID(&auth_id, &built.users[0].cmd_key, now, .{ 1, 2, 3, 4 });

    const user1 = try v.match(&auth_id, now);
    try std.testing.expectEqualStrings("pb8lpgli", user1.email);
    // 同 AuthID 立即重放 → Replay
    try std.testing.expectError(MatchError.Replay, v.match(&auth_id, now));

    // 换 rnd 生成新 AuthID → 命中
    var auth_id2: [16]u8 = undefined;
    vmess_aead.createAuthID(&auth_id2, &built.users[0].cmd_key, now, .{ 5, 6, 7, 8 });
    _ = try v.match(&auth_id2, now);

    // 时间窗 ±120s 边界：+119s 合法
    var auth_id3: [16]u8 = undefined;
    vmess_aead.createAuthID(&auth_id3, &built.users[0].cmd_key, now + 119, .{ 9, 9, 9, 9 });
    _ = try v.match(&auth_id3, now);

    // +121s → InvalidTime
    var auth_id4: [16]u8 = undefined;
    vmess_aead.createAuthID(&auth_id4, &built.users[0].cmd_key, now + 121, .{ 1, 1, 1, 1 });
    try std.testing.expectError(MatchError.InvalidTime, v.match(&auth_id4, now));

    // 未知用户（随机 AuthID）→ NotFound（大概率 crc 不过；兜底 NotFound）
    var bad = auth_id;
    bad[0] ^= 0xFF;
    const r = v.match(&bad, now) catch |e| e;
    try std.testing.expect(r == MatchError.NotFound or r == MatchError.InvalidTime);
}
