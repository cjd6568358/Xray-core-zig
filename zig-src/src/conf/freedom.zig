//! freedom 出站配置（上游 infra/conf/freedom.go 的 finalRules 子集）。

const std = @import("std");

pub const RuleAction = enum(u8) {
    allow = 0,
    block = 1,
};

pub const Network = enum(u8) {
    tcp,
    udp,
    any,
};

pub const PortRange = struct {
    from: u16,
    to: u16,
};

pub const IpRule = struct {
    /// CIDR 字节（4 或 16），前缀位数
    prefix: []const u8,
    bits: u8,
};

pub const FinalRule = struct {
    action: []const u8 = "allow",
    network: ?[]const u8 = null, // "tcp" / "udp" / "tcp,udp"
    port: ?[]const u8 = null, // "443" / "1000-2000"
    ip: ?[]const u8 = null, // CIDR 逗号分隔
    blockDelayFrom: ?u64 = null,
    blockDelayTo: ?u64 = null,

    pub const Error = error{
        UnknownAction,
        BadNetwork,
        BadPort,
        BadIpRule,
        OutOfMemory,
    };

    pub const Built = struct {
        action: RuleAction,
        networks: []const Network = &.{}, // 空 = 全部
        ports: []const PortRange = &.{}, // 空 = 全部
        ip_rules: []const IpRule = &.{}, // 空 = 全部
        block_delay_min: u64 = 30,
        block_delay_max: u64 = 90,

        pub fn matchNetwork(self: Built, n: Network) bool {
            if (self.networks.len == 0) return true;
            for (self.networks) |nw| {
                if (nw == n) return true;
            }
            return false;
        }

        pub fn matchPort(self: Built, port: u16) bool {
            if (self.ports.len == 0) return true;
            for (self.ports) |r| {
                if (r.from <= port and port <= r.to) return true;
            }
            return false;
        }

        pub fn matchIp(self: Built, ip: []const u8) bool {
            if (self.ip_rules.len == 0) return true;
            if (ip.len != 4 and ip.len != 16) return false;
            for (self.ip_rules) |r| {
                if (r.prefix.len != ip.len) continue;
                if (prefixMatch(ip, r.prefix, r.bits)) return true;
            }
            return false;
        }
    };

    fn prefixMatch(ip: []const u8, prefix: []const u8, bits: u8) bool {
        const full = bits / 8;
        if (!std.mem.eql(u8, ip[0..full], prefix[0..full])) return false;
        const rem = bits % 8;
        if (rem == 0) return true;
        const mask: u8 = @as(u8, 0xff) << @intCast(8 - rem);
        return (ip[full] & mask) == (prefix[full] & mask);
    }

    /// FreedomFinalRuleConfig.Build：action 归一 + network/port/ip 解析
    pub fn build(self: *const FinalRule, arena: std.mem.Allocator) Error!Built {
        var buf: [16]u8 = undefined;
        if (self.action.len > buf.len) return Error.UnknownAction;
        for (self.action, 0..) |c, i| buf[i] = std.ascii.toLower(c);
        const action = buf[0..self.action.len];

        const act: RuleAction = if (std.mem.eql(u8, action, "allow"))
            .allow
        else if (std.mem.eql(u8, action, "block"))
            .block
        else
            return Error.UnknownAction;

        var built = Built{ .action = act };

        if (self.network) |n| {
            var list: std.ArrayList(Network) = .empty;
            errdefer list.deinit(arena);
            var it = std.mem.splitScalar(u8, n, ',');
            while (it.next()) |part_raw| {
                const part = std.mem.trim(u8, part_raw, " ");
                if (part.len == 0) continue;
                if (std.mem.eql(u8, part, "tcp")) {
                    list.append(arena, .tcp) catch return Error.OutOfMemory;
                } else if (std.mem.eql(u8, part, "udp")) {
                    list.append(arena, .udp) catch return Error.OutOfMemory;
                } else {
                    return Error.BadNetwork;
                }
            }
            built.networks = list.items;
        }

        if (self.port) |p| {
            var ranges: std.ArrayList(PortRange) = .empty;
            errdefer ranges.deinit(arena);
            var it = std.mem.splitScalar(u8, p, ',');
            while (it.next()) |part_raw| {
                const part = std.mem.trim(u8, part_raw, " ");
                if (part.len == 0) continue;
                if (std.mem.indexOfScalar(u8, part, '-')) |dash| {
                    const from = std.fmt.parseInt(u32, std.mem.trim(u8, part[0..dash], " "), 10) catch return Error.BadPort;
                    const to = std.fmt.parseInt(u32, std.mem.trim(u8, part[dash + 1 ..], " "), 10) catch return Error.BadPort;
                    if (from > 65535 or to > 65535 or from > to) return Error.BadPort;
                    ranges.append(arena, .{ .from = @intCast(from), .to = @intCast(to) }) catch return Error.OutOfMemory;
                } else {
                    const v = std.fmt.parseInt(u32, part, 10) catch return Error.BadPort;
                    if (v > 65535) return Error.BadPort;
                    ranges.append(arena, .{ .from = @intCast(v), .to = @intCast(v) }) catch return Error.OutOfMemory;
                }
            }
            built.ports = ranges.items;
        }

        if (self.ip) |ips| {
            var rules: std.ArrayList(IpRule) = .empty;
            errdefer rules.deinit(arena);
            var it = std.mem.splitScalar(u8, ips, ',');
            while (it.next()) |part_raw| {
                const part = std.mem.trim(u8, part_raw, " ");
                if (part.len == 0) continue;
                const slash = std.mem.indexOfScalar(u8, part, '/') orelse return Error.BadIpRule;
                const addr_s = part[0..slash];
                const bits = std.fmt.parseInt(u8, part[slash + 1 ..], 10) catch return Error.BadIpRule;
                const a = @import("../common/net.zig").Address.parseIpLiteral(addr_s) orelse return Error.BadIpRule;
                const bytes: []const u8 = switch (a) {
                    .ipv4 => |b4| arena.dupe(u8, b4[0..]) catch return Error.OutOfMemory,
                    .ipv6 => |b6| arena.dupe(u8, b6[0..]) catch return Error.OutOfMemory,
                    .domain => return Error.BadIpRule,
                };
                const max_bits: u8 = @intCast(bytes.len * 8);
                if (bits > max_bits) return Error.BadIpRule;
                rules.append(arena, .{ .prefix = bytes, .bits = bits }) catch return Error.OutOfMemory;
            }
            built.ip_rules = rules.items;
        }

        if (self.blockDelayFrom != null and self.blockDelayTo != null) {
            built.block_delay_min = self.blockDelayFrom.?;
            built.block_delay_max = self.blockDelayTo.?;
        }
        return built;
    }
};

pub const FreedomConfig = struct {
    domainStrategy: ?[]const u8 = null,
    finalRules: []const FinalRule = &.{},
    /// M35 新增，可选：拨号单次超时（毫秒）。缺省 = 与上游一致，行为不变。
    dialTimeoutMs: ?u64 = null,
    /// M35 新增，可选：拨号重试次数。缺省 = 与上游一致，行为不变。
    dialAttempts: ?u64 = null,
    // 上游已移除并告警的遗留字段（出现时告警一次，等价于忽略）
    ipsBlocked: ?std.json.Value = null,
    ipsBlocked4: ?std.json.Value = null,

    pub const Built = struct {
        final_rules: []const FinalRule.Built,
        dial_timeout_ms: i64 = default_dial_timeout_ms,
        dial_attempts: usize = default_dial_attempts,
    };

    pub fn build(self: *const FreedomConfig, arena: std.mem.Allocator, logger: anytype) !Built {
        // 遗留字段移除告警（逐字对齐上游）
        if (self.ipsBlocked != null or self.ipsBlocked4 != null) {
            logger.warning("The feature \"ipsBlocked\" has been removed and migrated to \"finalRules\". Please update your config(s) according to release note and documentation.");
        }
        var rules: std.ArrayList(FinalRule.Built) = .empty;
        errdefer rules.deinit(arena);
        for (self.finalRules) |*r| {
            const built = try r.build(arena);
            rules.append(arena, built) catch return error.OutOfMemory;
        }
        return .{
            .final_rules = rules.items,
            .dial_timeout_ms = clampedTimeout(self.dialTimeoutMs, logger),
            .dial_attempts = clampedAttempts(self.dialAttempts, logger),
        };
    }
};

// ============================ M35：拨号参数可调 ============================
//
// 单一真源：这四个默认值与 proxy/freedom.zig 的 Handler 字段同源，
// 任一侧改动都会被编译期捕获，避免出现"两处魔数互不一致"。
//
// 【为什么改成可调】光猫实测（本次观察窗口 8.45h / 2312 连接）：
// 149 条出站拨号失败耗时 p50=81218ms，全部落在出口不可达的目标上
// （Google 系 111 条 + 测速节点 32 条）。成因是三个常数相乘：
//   单次超时 16s × 重试 5 次 + 退避 1s ≈ 81s
// 每条这样的连接白白占住「线程 + fd + 并发槽」81 秒，合计约 3.35h / 8.45h。
//
// 【为什么不直接改死默认】反向证据：成功拨号的 dial_ms 本身有重尾
// （p95=66ms 但 p99=19061ms、max=79806ms，其中 37 条 >5s 最终仍然连上）。
// 这些连接靠的正是后续重试才成功 —— 若把 attempts 硬砍到 3，会把
// "慢成功"扭成"失败"，是真实的体验倒退。
// 故：**默认值保持上游原样，仅在 xray.json 里显式调参**，随时可改回、不必重编译。

/// 单次 connect 超时（对应上游 freedom 的 dial timeout）
pub const default_dial_timeout_ms: i64 = 16 * 1000;
/// 拨号尝试次数（对应上游 retry.ExponentialBackoff(5, 100)）
pub const default_dial_attempts: usize = 5;
/// 退避基数（0/100/200/300/400ms）
pub const default_dial_backoff_base_ms: u32 = 100;

pub const min_dial_timeout_ms: i64 = 100;
pub const max_dial_timeout_ms: i64 = 60 * 1000;
pub const min_dial_attempts: usize = 1;
pub const max_dial_attempts: usize = 10;

/// 越界值静默回落默认并告警一次：保证"配置缺失/手滑写错 = 原行为"，
/// 不引入新的启动失败路径。
fn clampedTimeout(v: ?u64, logger: anytype) i64 {
    const raw = v orelse return default_dial_timeout_ms;
    if (raw < min_dial_timeout_ms or raw > max_dial_timeout_ms) {
        // logger 的 warning 只收整串（见 app/log.zig），先落缓冲再告警
        var b: [160]u8 = undefined;
        const m = std.fmt.bufPrint(&b, "freedom dialTimeoutMs={d} out of range [{d},{d}], fallback to {d}", .{
            raw, min_dial_timeout_ms, max_dial_timeout_ms, default_dial_timeout_ms,
        }) catch return default_dial_timeout_ms;
        logger.warning(m);
        return default_dial_timeout_ms;
    }
    return @intCast(raw);
}

fn clampedAttempts(v: ?u64, logger: anytype) usize {
    const raw = v orelse return default_dial_attempts;
    if (raw < min_dial_attempts or raw > max_dial_attempts) {
        var b: [160]u8 = undefined;
        const m = std.fmt.bufPrint(&b, "freedom dialAttempts={d} out of range [{d},{d}], fallback to {d}", .{
            raw, min_dial_attempts, max_dial_attempts, default_dial_attempts,
        }) catch return default_dial_attempts;
        logger.warning(m);
        return default_dial_attempts;
    }
    return @intCast(raw);
}

test "final rule allow-all (xray.json 形态)" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const r = FinalRule{ .action = "allow" };
    const b = try r.build(arena_state.allocator());
    try std.testing.expectEqual(RuleAction.allow, b.action);
    try std.testing.expect(b.matchNetwork(.tcp));
    try std.testing.expect(b.matchNetwork(.udp));
    try std.testing.expect(b.matchPort(1));
    try std.testing.expect(b.matchIp(&.{ 10, 0, 0, 1 }));
}

test "final rule block with port and ip matchers" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const r = FinalRule{
        .action = "block",
        .network = "tcp,udp",
        .port = "80,443,1000-2000",
        .ip = "10.0.0.0/8,192.168.1.1/32",
    };
    const b = try r.build(arena);
    try std.testing.expectEqual(RuleAction.block, b.action);
    try std.testing.expect(b.matchNetwork(.tcp));
    try std.testing.expect(b.matchPort(443));
    try std.testing.expect(b.matchPort(1500));
    try std.testing.expect(!b.matchPort(8080));
    try std.testing.expect(b.matchIp(&.{ 10, 1, 2, 3 }));
    try std.testing.expect(b.matchIp(&.{ 192, 168, 1, 1 }));
    try std.testing.expect(!b.matchIp(&.{ 11, 0, 0, 1 }));
    try std.testing.expect(!b.matchIp(&.{ 192, 168, 1, 2 }));
}

test "final rule unknown action rejected (upstream message path)" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const r = FinalRule{ .action = "forward" };
    try std.testing.expectError(FinalRule.Error.UnknownAction, r.build(arena_state.allocator()));
}

// ============================ M35：拨号参数可调 ============================

/// 兜底 logger：记录是否告警过（conf 层的告警我不能依赖真实 Logger 输出）
const WarnSpy = struct {
    n: usize = 0,
    last: [160]u8 = undefined,
    last_len: usize = 0,
    pub fn warning(self: *WarnSpy, msg: []const u8) void {
        self.n += 1;
        if (msg.len <= self.last.len) {
            @memcpy(self.last[0..msg.len], msg);
            self.last_len = msg.len;
        }
    }
};

test "M35: 缺省 = 上游默认行为，零行为变更" {
    var spy = WarnSpy{};
    const c = FreedomConfig{ .finalRules = &.{} };
    try std.testing.expectEqual(default_dial_timeout_ms, clampedTimeout(c.dialTimeoutMs, &spy));
    try std.testing.expectEqual(default_dial_attempts, clampedAttempts(c.dialAttempts, &spy));
    try std.testing.expectEqual(@as(i64, 16 * 1000), default_dial_timeout_ms);
    try std.testing.expectEqual(@as(usize, 5), default_dial_attempts);
    try std.testing.expectEqual(@as(usize, 0), spy.n); // 缺省路径不产生告警
}

test "M35: 合法值生效（本设备调优形态 8000ms）" {
    var spy = WarnSpy{};
    try std.testing.expectEqual(@as(i64, 8000), clampedTimeout(8000, &spy));
    try std.testing.expectEqual(@as(usize, 5), clampedAttempts(5, &spy));
    try std.testing.expectEqual(@as(usize, 0), spy.n);
}

test "M35: 越界/零值静默回落默认，不引入启动失败路径" {
    var spy = WarnSpy{};
    // 0 —— JSON 里写 "" 或 0 都是手滑，必须回落而不是"0ms 超时"自杀
    try std.testing.expectEqual(default_dial_timeout_ms, clampedTimeout(0, &spy));
    try std.testing.expectEqual(default_dial_attempts, clampedAttempts(0, &spy));
    try std.testing.expectEqual(@as(usize, 2), spy.n);

    spy = WarnSpy{};
    try std.testing.expectEqual(default_dial_timeout_ms, clampedTimeout(999999, &spy));
    try std.testing.expectEqual(default_dial_attempts, clampedAttempts(999, &spy));
    try std.testing.expectEqual(@as(usize, 2), spy.n);
}

test "M35: 边界值取得到（含端点）" {
    var spy = WarnSpy{};
    try std.testing.expectEqual(min_dial_timeout_ms, clampedTimeout(min_dial_timeout_ms, &spy));
    try std.testing.expectEqual(max_dial_timeout_ms, clampedTimeout(max_dial_timeout_ms, &spy));
    try std.testing.expectEqual(min_dial_attempts, clampedAttempts(min_dial_attempts, &spy));
    try std.testing.expectEqual(max_dial_attempts, clampedAttempts(max_dial_attempts, &spy));
    try std.testing.expectEqual(@as(usize, 0), spy.n);
}

test "M35: FreedomConfig.build 把拨号参数带到 Built" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    var spy = WarnSpy{};
    const c = FreedomConfig{
        .finalRules = &.{.{ .action = "allow" }},
        .dialTimeoutMs = 8000,
        .dialAttempts = 5,
    };
    const b = try c.build(arena_state.allocator(), &spy);
    try std.testing.expectEqual(@as(i64, 8000), b.dial_timeout_ms);
    try std.testing.expectEqual(@as(usize, 5), b.dial_attempts);
    try std.testing.expectEqual(@as(usize, 1), b.final_rules.len);
}
