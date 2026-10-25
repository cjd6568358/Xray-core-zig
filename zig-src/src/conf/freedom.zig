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
    // 上游已移除并告警的遗留字段（出现时告警一次，等价于忽略）
    ipsBlocked: ?std.json.Value = null,
    ipsBlocked4: ?std.json.Value = null,

    pub const Built = struct {
        final_rules: []const FinalRule.Built,
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
        return .{ .final_rules = rules.items };
    }
};

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
