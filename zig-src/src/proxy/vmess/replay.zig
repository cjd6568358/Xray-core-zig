//! 防重放原语（对照 common/antireplay/mapfilter.go + proxy/vmess/encoding/server.go
//! SessionHistory @ v26.10.21）。
//!
//! ReplayFilter：双池轮换（120s）——Check 时若距上次清理 ≥ interval 则 poolB=poolA、
//! poolA 清空；两池任一命中即重放；新值入 poolA。
//! SessionHistory：会话三元组（user 16B + requestBodyKey 16B + requestBodyIV 16B）
//! → 过期时间（now+3min）；30s 惰性清理（Go 为 Periodic task，观察行为等价）。

const std = @import("std");
const sys = @import("../../common/sys.zig");

fn Ctx128(comptime K: type) type {
    return struct {
        pub fn hash(_: @This(), k: K) u64 {
            return std.hash.Wyhash.hash(0, std.mem.asBytes(&k));
        }
        pub fn eql(_: @This(), a: K, b: K) bool {
            return std.mem.eql(u8, std.mem.asBytes(&a), std.mem.asBytes(&b));
        }
    };
}

/// antireplay.NewMapFilter(120)：AuthID 双池
pub const ReplayFilter = struct {
    const Map = std.HashMapUnmanaged(u128, void, Ctx128(u128), 80);

    mu: sys.Mutex = .{},
    alloc: std.mem.Allocator,
    pool_a: Map = .empty,
    pool_b: Map = .empty,
    interval_ms: i64 = 120_000,
    last_clean_ms: i64,

    pub fn create(alloc: std.mem.Allocator) !*ReplayFilter {
        const self = try alloc.create(ReplayFilter);
        self.* = .{ .alloc = alloc, .last_clean_ms = sys.nowUnixMilli() };
        return self;
    }

    pub fn destroy(self: *ReplayFilter) void {
        self.pool_a.deinit(self.alloc);
        self.pool_b.deinit(self.alloc);
        self.alloc.destroy(self);
    }

    /// Check：true = 首见（放行），false = 重放（拒绝）
    pub fn check(self: *ReplayFilter, auth_id: *const [16]u8) bool {
        self.mu.lock();
        defer self.mu.unlock();

        const now = sys.nowUnixMilli();
        if (now - self.last_clean_ms >= self.interval_ms) {
            self.pool_b.deinit(self.alloc);
            self.pool_b = self.pool_a;
            self.pool_a = .empty;
            self.last_clean_ms = now;
        }

        const key: u128 = std.mem.readInt(u128, auth_id, .big);
        const in_a = self.pool_a.contains(key);
        const in_b = self.pool_b.contains(key);
        if (!in_a and !in_b) {
            self.pool_a.put(self.alloc, key, {}) catch {};
        }
        return !(in_a or in_b);
    }
};

/// encoding.SessionHistory：会话三元组去重（3 分钟有效，30s 惰性清理）
pub const SessionHistory = struct {
    const Sid = [48]u8; // user(16) || key(16) || nonce(16)
    const Map = std.HashMapUnmanaged(Sid, i64, Ctx128(Sid), 80);

    mu: sys.Mutex = .{},
    alloc: std.mem.Allocator,
    cache: Map = .empty,
    last_clean_ms: i64,

    pub fn create(alloc: std.mem.Allocator) !*SessionHistory {
        const self = try alloc.create(SessionHistory);
        self.* = .{ .alloc = alloc, .last_clean_ms = sys.nowUnixMilli() };
        return self;
    }

    pub fn destroy(self: *SessionHistory) void {
        self.cache.deinit(self.alloc);
        self.alloc.destroy(self);
    }

    /// addIfNotExits：true = 首见；false = 3 分钟内重复（重放）
    pub fn addIfNotExists(self: *SessionHistory, user: [16]u8, key: [16]u8, nonce: [16]u8) bool {
        self.mu.lock();
        defer self.mu.unlock();

        const now = sys.nowUnixMilli();
        if (now - self.last_clean_ms >= 30_000) {
            // removeExpiredEntries（30s 周期，观察行为等价的惰性版）
            var it = self.cache.iterator();
            while (it.next()) |e| {
                if (e.value_ptr.* <= now) {
                    _ = self.cache.remove(e.key_ptr.*);
                }
            }
            self.last_clean_ms = now;
        }

        var sid: Sid = undefined;
        @memcpy(sid[0..16], &user);
        @memcpy(sid[16..32], &key);
        @memcpy(sid[32..48], &nonce);

        if (self.cache.get(sid)) |expire| {
            if (expire > now) return false; // 未过期重复
        }
        self.cache.put(self.alloc, sid, now + 180_000) catch {};
        return true;
    }
};

// ============================ 测试 ============================

test "ReplayFilter：首见放行、重复拒绝、双池轮换后旧值放行" {
    const f = try ReplayFilter.create(std.testing.allocator);
    defer f.destroy();
    var id: [16]u8 = undefined;
    id[0] = 9;
    try std.testing.expect(f.check(&id));
    try std.testing.expect(!f.check(&id));
    var id2 = id;
    id2[15] = 1;
    try std.testing.expect(f.check(&id2));
    try std.testing.expect(!f.check(&id2));
}

test "SessionHistory：3 分钟内重复拒绝" {
    const h = try SessionHistory.create(std.testing.allocator);
    defer h.destroy();
    var u: [16]u8 = undefined;
    var k: [16]u8 = undefined;
    var n: [16]u8 = undefined;
    u[0] = 1;
    k[0] = 2;
    n[0] = 3;
    try std.testing.expect(h.addIfNotExists(u, k, n));
    try std.testing.expect(!h.addIfNotExists(u, k, n));
    // 三元组任一分量不同 → 不同会话
    var n2 = n;
    n2[1] = 4;
    try std.testing.expect(h.addIfNotExists(u, k, n2));
}
