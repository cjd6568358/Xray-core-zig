//! M8 conf 层测试（移植上游 infra/conf/{vless,vmess,freedom,transport}_test.go
//! 中本子集有用例；其余入站/出站专属形态属 Phase 2，未移植）。
//!
//! 覆盖点：
//!   1. vmess 入站 per-client security 字段（上游 TestVMessInbound；default→AUTO 不报错）
//!   2. vless 入站 fallbacks 容忍（非 fallback 路径：解析通过、客户端照常构建）
//!   3. freedom domainStrategy/redirect/userLevel/sockopt 等非本子集字段容忍
//!   4. streamSettings sockopt（mark/tcpFastOpen/dialerProxy）容忍 + tcp 别名
//!   5. freedom ipsBlocked 遗留字段移除告警路径

const std = @import("std");
const vmess = @import("../src/conf/vmess.zig");
const vless = @import("../src/conf/vless.zig");
const freedom = @import("../src/conf/freedom.zig");
const transport = @import("../src/conf/transport.zig");
const log = @import("../src/app/log.zig");

const parse_opts = std.json.ParseOptions{ .ignore_unknown_fields = true };

test "conf: vmess 入站 per-client security（上游 TestVMessInbound）" {
    const text =
        \\{"clients": [
        \\    {
        \\        "id": "27848739-7e62-4138-9fd3-098a63964b6b",
        \\        "level": 0,
        \\        "email": "love@example.com",
        \\        "security": "aes-128-gcm"
        \\    }
        \\],
        \\"default": { "level": 0 }}
    ;
    var parsed = try std.json.parseFromSlice(vmess.VmessInboundConfig, std.testing.allocator, text, parse_opts);
    defer parsed.deinit();
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const built = try parsed.value.build(arena_state.allocator());
    try std.testing.expectEqual(@as(usize, 1), built.users.len);
    try std.testing.expectEqualStrings("love@example.com", built.users[0].email);
    // aes-128-gcm → SecurityType_AES128_GCM(3)
    try std.testing.expectEqual(@as(u8, 0x03), built.users[0].security);
}

test "conf: vmess security 未知值/缺省 → AUTO(2)（上游 default 分支不报错）" {
    const cases = [_]struct { text: []const u8, sec: u8 }{
        .{ .text =
            \\{"clients":[{"id":"27848739-7e62-4138-9fd3-098a63964b6b","security":"whatever"}]}
        , .sec = 0x02 },
        .{ .text =
            \\{"clients":[{"id":"27848739-7e62-4138-9fd3-098a63964b6b"}]}
        , .sec = 0x02 },
        .{ .text =
            \\{"clients":[{"id":"27848739-7e62-4138-9fd3-098a63964b6b","security":"chacha20-poly1305"}]}
        , .sec = 0x04 },
    };
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    for (cases) |c| {
        var parsed = try std.json.parseFromSlice(vmess.VmessInboundConfig, std.testing.allocator, c.text, parse_opts);
        defer parsed.deinit();
        const built = try parsed.value.build(arena);
        try std.testing.expectEqual(c.sec, built.users[0].security);
    }
}

test "conf: vless 入站 fallbacks 三形态解析（M16：上游 TestVLessInbound 同款，本版已支持）" {
    // 上游 TestVLessInbound 的三种 fallback 形态：数字 dest（端口）、alpn+unix socket、
    // path+tag。M16 起本版支持 fallbacks，build 不再拒绝。
    const text =
        \\{"clients": [
        \\    {
        \\        "id": "27848739-7e62-4138-9fd3-098a63964b6b",
        \\        "level": 0,
        \\        "email": "love@example.com"
        \\    }
        \\],
        \\"decryption": "none",
        \\"fallbacks": [
        \\    { "dest": 80 },
        \\    { "alpn": "h2", "dest": "@/dev/shm/domain.socket", "xver": 2 },
        \\    { "path": "/innerws", "dest": "serve-ws-none" }
        \\]}
    ;
    var parsed = try std.json.parseFromSlice(vless.VlessInboundConfig, std.testing.allocator, text, parse_opts);
    defer parsed.deinit();
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const built = try parsed.value.build(arena_state.allocator());
    try std.testing.expectEqual(@as(usize, 1), built.users.len);
    try std.testing.expectEqual(@as(usize, 3), built.fallbacks.len);
    // 字段透传：path/xver/alpn
    try std.testing.expectEqualStrings("/innerws", built.fallbacks[2].path);
    try std.testing.expectEqualStrings("serve-ws-none", built.fallbacks[2].dest);
    try std.testing.expectEqual(@as(u64, 2), built.fallbacks[1].xver);
    try std.testing.expectEqualStrings("h2", built.fallbacks[1].alpn);
    // 缺省：type 默认 tcp、xver 默认 0
    try std.testing.expectEqualStrings("tcp", built.fallbacks[0].type);
    try std.testing.expectEqual(@as(u64, 0), built.fallbacks[0].xver);
    // dest 数字归一为字符串（上游 protojson 容错语义）
    try std.testing.expectEqualStrings("80", built.fallbacks[0].dest);
}

test "conf: freedom domainStrategy/redirect/userLevel 容忍（上游 TestFreedomConfig 字段集）" {
    const text =
        \\{
        \\    "domainStrategy": "AsIs",
        \\    "redirect": "127.0.0.1:3366",
        \\    "userLevel": 1,
        \\    "finalRules": [ { "action": "allow" } ]
        \\}
    ;
    var parsed = try std.json.parseFromSlice(freedom.FreedomConfig, std.testing.allocator, text, parse_opts);
    defer parsed.deinit();
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    var lg = log.Logger{ .enabled = false };
    const built = try parsed.value.build(arena_state.allocator(), &lg);
    try std.testing.expectEqual(@as(usize, 1), built.final_rules.len);
    try std.testing.expectEqual(freedom.RuleAction.allow, built.final_rules[0].action);
}

test "conf: freedom ipsBlocked 遗留字段 → 移除告警 + 规则为空" {
    const text =
        \\{ "ipsBlocked": ["0.0.0.0"], "finalRules": [] }
    ;
    var parsed = try std.json.parseFromSlice(freedom.FreedomConfig, std.testing.allocator, text, parse_opts);
    defer parsed.deinit();
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    var lg = log.Logger{ .enabled = false };
    const built = try parsed.value.build(arena_state.allocator(), &lg);
    try std.testing.expectEqual(@as(usize, 0), built.final_rules.len);
}

test "conf: streamSettings sockopt 容忍 + tcp/raw 别名（上游 socket 设置子集）" {
    const text =
        \\{
        \\    "network": "tcp",
        \\    "security": "none",
        \\    "sockopt": {
        \\        "mark": 1,
        \\        "tcpFastOpen": true,
        \\        "domainStrategy": "UseIP",
        \\        "dialerProxy": "tag"
        \\    }
        \\}
    ;
    var parsed = try std.json.parseFromSlice(transport.StreamConfig, std.testing.allocator, text, parse_opts);
    defer parsed.deinit();
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    var lg = log.Logger{ .enabled = false };
    const built = try parsed.value.build(arena_state.allocator(), &lg);
    try std.testing.expectEqualStrings("tcp", built.protocol_name);
    try std.testing.expectEqualStrings("none", built.security);
    try std.testing.expect(built.kcp == null);
    try std.testing.expect(built.ws == null);

    // raw 别名 → tcp
    const text2 =
        \\{ "network": "raw", "security": "none" }
    ;
    var parsed2 = try std.json.parseFromSlice(transport.StreamConfig, std.testing.allocator, text2, parse_opts);
    defer parsed2.deinit();
    const built2 = try parsed2.value.build(arena_state.allocator(), &lg);
    try std.testing.expectEqualStrings("tcp", built2.protocol_name);
}

test "conf: policy 段解析（M15 统计开关，上游 camelCase 键）" {
    const conf = @import("../src/conf/config.zig");
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const json_text =
        \\ {
        \\   "log": { "loglevel": "warning" },
        \\   "policy": {
        \\     "system": { "statsInboundUplink": true, "statsInboundDownlink": false },
        \\     "user": [ { "email": "pb8lpgli", "level": 0, "statsUplink": true, "statsDownlink": true } ]
        \\   },
        \\   "inbounds": [ { "tag": "in0", "port": 19001, "protocol": "vless", "settings": { "clients": [ { "id": "de53e864-8530-4212-a3d7-c31e60b62e91" } ] } } ],
        \\   "outbounds": [ { "tag": "direct", "protocol": "freedom", "settings": { "finalRules": [ { "action": "allow" } ] } } ]
        \\ }
    ;
    const root = try conf.parseRoot(arena, json_text);
    try std.testing.expect(root.policy.system.statsInboundUplink);
    try std.testing.expect(!root.policy.system.statsInboundDownlink);
    try std.testing.expectEqual(@as(usize, 1), root.policy.user.len);
    try std.testing.expectEqualStrings("pb8lpgli", root.policy.user[0].email);
    try std.testing.expect(root.policy.user[0].statsUplink);
    try std.testing.expect(root.policy.user[0].statsDownlink);
}

test "conf: policy 缺省 → 全关（上游 SessionDefault.Stats 默认 false）" {
    const conf = @import("../src/conf/config.zig");
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const json_text =
        \\ {
        \\   "log": { "loglevel": "warning" },
        \\   "inbounds": [ { "tag": "in0", "port": 19001, "protocol": "vless", "settings": { "clients": [ { "id": "de53e864-8530-4212-a3d7-c31e60b62e91" } ] } } ],
        \\   "outbounds": [ { "tag": "direct", "protocol": "freedom", "settings": { "finalRules": [ { "action": "allow" } ] } } ]
        \\ }
    ;
    const root = try conf.parseRoot(arena, json_text);
    try std.testing.expect(!root.policy.system.statsInboundUplink);
    try std.testing.expect(!root.policy.system.statsInboundDownlink);
    try std.testing.expectEqual(@as(usize, 0), root.policy.user.len);
}
