//! 顶层配置（上游 infra/conf/serial + xray.go 的服务端子集）。
//! JSON 键与结构体字段逐字一致；未知字段容忍（ignore_unknown_fields）；
//! 遗留字段（alterId 等）静默忽略；不支持项显式报错（exit 23）。

const std = @import("std");
const log = @import("../app/log.zig");
const transport = @import("transport.zig");
const freedom = @import("freedom.zig");
const vless = @import("vless.zig");
const vmess = @import("vmess.zig");
const net = @import("../common/net.zig");

pub const ConfigError = error{
    BadJson,
    InvalidListen,
    PortRequired,
    UnsupportedInboundProtocol,
    UnsupportedOutboundProtocol,
    OutboundRequired,
    SettingsMissing,
    // 转发自下层（诊断消息里给细节）
    Transport,
    Vless,
    Vmess,
    Freedom,
    OutOfMemory,
};

/// 诊断消息（固定缓冲，主流程打印用）
pub const Diag = struct {
    buf: [512]u8 = undefined,
    len: usize = 0,

    pub fn message(self: *const Diag) []const u8 {
        return self.buf[0..self.len];
    }

    pub fn set(self: *Diag, comptime fmt: []const u8, args: anytype) void {
        const s = std.fmt.bufPrint(&self.buf, fmt, args) catch {
            self.len = 0;
            return;
        };
        self.len = s.len;
    }
};

pub const LogConfig = struct {
    loglevel: []const u8 = "warning",
    access: []const u8 = "",
    errorlog: []const u8 = "", // json 键 "error"
    /// 连接生命周期打点粒度（app/trace.zig）：off / summary（默认）/ full。
    /// 与 loglevel 正交：loglevel 决定"能不能打出来"，trace 决定"打多细"。
    trace: []const u8 = "summary",
};

/// policy 段（对照 app/policy config.proto：system/user 两级）
pub const PolicyConfig = struct {
    system: SystemPolicyConfig = .{},
    user: []const UserPolicyConfig = &.{},
};

pub const SystemPolicyConfig = struct {
    /// 上游默认全部 false（features/policy SessionDefault.Stats）
    /// 键名与上游配置一致（camelCase，同 streamSettings/kcpSettings 的项目惯例）
    statsInboundUplink: bool = false,
    statsInboundDownlink: bool = false,
};

pub const UserPolicyConfig = struct {
    /// 上游 Policy_User 的 email 字段
    email: []const u8 = "",
    level: u32 = 0,
    statsUplink: bool = false,
    statsDownlink: bool = false,
};

pub const InboundConfig = struct {
    tag: []const u8 = "",
    listen: []const u8 = "0.0.0.0",
    port: u16 = 0,
    protocol: []const u8 = "",
    settings: ?std.json.Value = null,
    streamSettings: ?transport.StreamConfig = null,
    sniffing: ?transport.SniffingConfig = null,
};

pub const OutboundConfig = struct {
    tag: []const u8 = "",
    protocol: []const u8 = "",
    settings: ?std.json.Value = null,
};

pub const RootConfig = struct {
    log: LogConfig = .{},
    policy: PolicyConfig = .{},
    inbounds: []const InboundConfig = &.{},
    outbounds: []const OutboundConfig = &.{},
};

/// 解析后的单入站运行时对象
pub const RuntimeInbound = struct {
    tag: []const u8,
    listen: net.Address,
    port: u16,
    protocol: []const u8, // "vless" / "vmess"
    stream: ?transport.StreamConfig.Built,
    sniffing_enabled: bool,
    vless_users: []const vless.VlessClient.Built = &.{},
    /// M16 VLESS fallbacks（上游 proxy/vless/inbound）：空 = 不启用回落
    vless_fallbacks: []const vless.Fallback = &.{},
    vmess_users: []const vmess.VmessClient.Built = &.{},
};

/// 解析后的单出站运行时对象
pub const RuntimeOutbound = struct {
    tag: []const u8,
    protocol: []const u8,
    freedom_rules: []const freedom.FinalRule.Built = &.{},
    /// M35：拨号参数（缺省 = conf/freedom.zig 的上游默认）
    dial_timeout_ms: i64 = freedom.default_dial_timeout_ms,
    dial_attempts: usize = freedom.default_dial_attempts,
};

pub const RuntimeConfig = struct {
    log_level: log.LogLevel,
    access_path: []const u8,
    /// 连接打点粒度（log.trace）；main 启动时赋给 Logger.trace_level
    trace_level: log.TraceLevel = .summary,
    policy: PolicyConfig = .{},
    inbounds: []const RuntimeInbound,
    outbounds: []const RuntimeOutbound,
    default_outbound: usize, // 无 routing 时恒走 outbounds 顺序第一个（表 4-1）

    pub fn findInboundByTag(self: *const RuntimeConfig, tag: []const u8) ?*const RuntimeInbound {
        for (self.inbounds) |*ib| {
            if (std.mem.eql(u8, ib.tag, tag)) return ib;
        }
        return null;
    }
};

/// 解析 JSON 文本为 RootConfig（未知字段容忍）
pub fn parseRoot(arena: std.mem.Allocator, bytes: []const u8) ConfigError!RootConfig {
    return std.json.parseFromSliceLeaky(RootConfig, arena, bytes, .{
        .ignore_unknown_fields = true,
    }) catch return ConfigError.BadJson;
}

const parse_opts = std.json.ParseOptions{ .ignore_unknown_fields = true };

/// RootConfig → RuntimeConfig（校验全部在此，失败时 diag 给出上游风格错误消息）
pub fn buildRuntime(arena: std.mem.Allocator, logger: *log.Logger, root: *const RootConfig, diag: *Diag) ConfigError!RuntimeConfig {
    var inbounds: std.ArrayList(RuntimeInbound) = .empty;
    errdefer inbounds.deinit(arena);
    for (root.inbounds) |*ib| {
        const built = try buildInbound(arena, logger, ib, diag);
        inbounds.append(arena, built) catch return ConfigError.OutOfMemory;
    }

    var outbounds: std.ArrayList(RuntimeOutbound) = .empty;
    errdefer outbounds.deinit(arena);
    for (root.outbounds, 0..) |*ob, i| {
        if (ob.protocol.len == 0 and ob.tag.len == 0) continue; // 空占位跳过
        const built = try buildOutbound(arena, logger, ob, diag);
        outbounds.append(arena, built) catch return ConfigError.OutOfMemory;
        _ = i;
    }
    if (outbounds.items.len == 0) {
        diag.set("no outbound found in config", .{});
        return ConfigError.OutboundRequired;
    }

    return .{
        .log_level = log.LogLevel.fromString(root.log.loglevel),
        .trace_level = log.TraceLevel.fromString(root.log.trace),
        .policy = root.policy,
        .access_path = root.log.access,
        .inbounds = inbounds.items,
        .outbounds = outbounds.items,
        .default_outbound = 0,
    };
}

fn buildInbound(arena: std.mem.Allocator, logger: *log.Logger, ib: *const InboundConfig, diag: *Diag) ConfigError!RuntimeInbound {
    // listen：localhost → 127.0.0.1；必须是 IP（域名监听报错）
    var listen_text = ib.listen;
    if (std.ascii.eqlIgnoreCase(listen_text, "localhost")) {
        listen_text = "127.0.0.1";
    }
    const listen = net.Address.parseIpLiteral(listen_text) orelse {
        diag.set("invalid listen address: {s}", .{ib.listen});
        return ConfigError.InvalidListen;
    };
    if (ib.port == 0) {
        diag.set("invalid port range: 0 for inbound {s}", .{ib.tag});
        return ConfigError.PortRequired;
    }

    var built = RuntimeInbound{
        .tag = ib.tag,
        .listen = listen,
        .port = ib.port,
        .protocol = ib.protocol,
        .stream = null,
        .sniffing_enabled = false,
    };

    if (ib.streamSettings) |*ss| {
        built.stream = transport.StreamConfig.build(ss, arena, logger) catch |e| {
            fillTransportDiag(diag, e, if (ss.network) |n| n else "tcp");
            return ConfigError.Transport;
        };
    }

    if (ib.sniffing) |*sn| {
        sn.validate() catch {
            diag.set("unknown sniffing type in destOverride", .{});
            return ConfigError.Transport;
        };
        built.sniffing_enabled = sn.enabled;
    }

    if (std.mem.eql(u8, ib.protocol, "vless")) {
        const sv = ib.settings orelse {
            diag.set("VLESS settings missing for inbound {s}", .{ib.tag});
            return ConfigError.SettingsMissing;
        };
        const parsed = std.json.parseFromValueLeaky(vless.VlessInboundConfig, arena, sv, parse_opts) catch {
            diag.set("VLESS settings: invalid user", .{});
            return ConfigError.Vless;
        };
        const users = parsed.build(arena) catch |e| {
            fillVlessDiag(diag, e);
            return ConfigError.Vless;
        };
        built.vless_users = users.users;
        built.vless_fallbacks = users.fallbacks;
    } else if (std.mem.eql(u8, ib.protocol, "vmess")) {
        const sv = ib.settings orelse {
            diag.set("VMess settings missing for inbound {s}", .{ib.tag});
            return ConfigError.SettingsMissing;
        };
        const parsed = std.json.parseFromValueLeaky(vmess.VmessInboundConfig, arena, sv, parse_opts) catch {
            diag.set("VMess settings: invalid user", .{});
            return ConfigError.Vmess;
        };
        const users = parsed.build(arena) catch {
            diag.set("invalid UUID in vmess clients", .{});
            return ConfigError.Vmess;
        };
        built.vmess_users = users.users;
    } else {
        diag.set("unsupported inbound protocol: {s} (Phase 1: vless/vmess only)", .{ib.protocol});
        return ConfigError.UnsupportedInboundProtocol;
    }
    return built;
}

fn buildOutbound(arena: std.mem.Allocator, logger: *log.Logger, ob: *const OutboundConfig, diag: *Diag) ConfigError!RuntimeOutbound {
    var built = RuntimeOutbound{ .tag = ob.tag, .protocol = ob.protocol };
    if (std.mem.eql(u8, ob.protocol, "freedom")) {
        if (ob.settings) |sv| {
            const parsed = std.json.parseFromValueLeaky(freedom.FreedomConfig, arena, sv, parse_opts) catch {
                diag.set("freedom settings: invalid", .{});
                return ConfigError.Freedom;
            };
            const f = parsed.build(arena, logger) catch {
                diag.set("freedom settings: invalid finalRules", .{});
                return ConfigError.Freedom;
            };
            built.freedom_rules = f.final_rules;
            built.dial_timeout_ms = f.dial_timeout_ms;
            built.dial_attempts = f.dial_attempts;
        }
    } else {
        diag.set("unsupported outbound protocol: {s} (Phase 1: freedom only)", .{ob.protocol});
        return ConfigError.UnsupportedOutboundProtocol;
    }
    return built;
}

fn fillTransportDiag(diag: *Diag, e: transport.ConfigBuildError, network: []const u8) void {
    switch (e) {
        transport.ConfigBuildError.UnknownTransportProtocol => diag.set("Config: unknown transport protocol: {s}", .{network}),
        transport.ConfigBuildError.RemovedTransportFeature => diag.set("removed transport feature (see log for details)", .{}),
        transport.ConfigBuildError.UnsupportedSecurity => diag.set("security must be none in Phase 1", .{}),
        transport.ConfigBuildError.KcpMtuTooSmall => diag.set("MTU must be at least 21", .{}),
        transport.ConfigBuildError.KcpTtiOutOfRange => diag.set("TTI must be between 10 and 1000", .{}),
        transport.ConfigBuildError.KcpCwndTooSmall => diag.set("CwndMultiplier must be at least 1", .{}),
        transport.ConfigBuildError.KcpSendingWindowTooSmall => diag.set("MaxSendingWindow must be at least <mtu>", .{}),
        else => diag.set("transport config error", .{}),
    }
}

fn fillVlessDiag(diag: *Diag, e: vless.ConfError) void {
    switch (e) {
        vless.ConfError.DecryptionNotNone => diag.set("VLESS \"decryption\" only supports \"none\" for now.", .{}),
        vless.ConfError.UnsupportedFlow => diag.set("VLESS users: \"flow\" doesn't support in this version", .{}),
        vless.ConfError.EncryptionInInbound => diag.set("VLESS users: \"encryption\" should not be in inbound settings", .{}),
        vless.ConfError.InvalidUuid => diag.set("invalid UUID in vless clients", .{}),
        else => diag.set("vless settings error", .{}),
    }
}

// ============================ 测试 ============================

const sample_config =
    \\{
    \\  "log": { "loglevel": "warning", "access": "/dev/null" },
    \\  "inbounds": [
    \\    {
    \\      "tag": "inbound-19001",
    \\      "listen": "0.0.0.0",
    \\      "port": 19001,
    \\      "protocol": "vless",
    \\      "settings": {
    \\        "clients": [ { "id": "de53e864-8530-4212-a3d7-c31e60b62e91", "email": "pb8lpgli", "flow": "" } ],
    \\        "decryption": "none"
    \\      },
    \\      "streamSettings": {
    \\        "network": "ws",
    \\        "security": "none",
    \\        "wsSettings": { "path": "/free", "host": "", "headers": { "Host": "ltetp.tv189.com" } }
    \\      },
    \\      "sniffing": { "enabled": false, "destOverride": ["http","tls","quic","fakedns"] }
    \\    },
    \\    {
    \\      "tag": "kcp-vmess",
    \\      "listen": "0.0.0.0",
    \\      "port": 19002,
    \\      "protocol": "vmess",
    \\      "settings": {
    \\        "clients": [ { "id": "de53e864-8530-4212-a3d7-c31e60b62e91", "alterId": 0, "email": "pb8lpgli" } ]
    \\      },
    \\      "streamSettings": {
    \\        "network": "kcp",
    \\        "security": "none",
    \\        "kcpSettings": { "mtu": 1250, "tti": 20, "uplinkCapacity": 20, "downlinkCapacity": 20, "congestion": false, "readBufferSize": 4, "writeBufferSize": 4 }
    \\      }
    \\    }
    \\  ],
    \\  "outbounds": [
    \\    { "protocol": "freedom", "tag": "direct", "settings": { "finalRules": [ { "action": "allow" } ] } }
    \\  ],
    \\  "someFutureSection": { "whatever": 1 }
    \\}
;

test "build runtime from xray.json sample" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var lg = log.Logger{ .enabled = false };
    var diag = Diag{};

    const root = try parseRoot(arena, sample_config);
    const rt = try buildRuntime(arena, &lg, &root, &diag);

    try std.testing.expectEqual(@as(usize, 2), rt.inbounds.len);
    try std.testing.expectEqual(@as(usize, 1), rt.outbounds.len);
    try std.testing.expectEqual(@as(usize, 0), rt.default_outbound);
    try std.testing.expectEqual(log.LogLevel.warning, rt.log_level);

    const vless_in = rt.inbounds[0];
    try std.testing.expectEqualStrings("inbound-19001", vless_in.tag);
    try std.testing.expectEqual(@as(u16, 19001), vless_in.port);
    try std.testing.expectEqualStrings("vless", vless_in.protocol);
    try std.testing.expectEqual(@as(usize, 1), vless_in.vless_users.len);
    try std.testing.expect(vless_in.stream != null);
    try std.testing.expectEqualStrings("websocket", vless_in.stream.?.protocol_name);
    try std.testing.expectEqualStrings("/free", vless_in.stream.?.ws.?.path);
    try std.testing.expectEqualStrings("ltetp.tv189.com", vless_in.stream.?.ws.?.host);
    try std.testing.expect(!vless_in.sniffing_enabled);

    const vmess_in = rt.inbounds[1];
    try std.testing.expectEqualStrings("kcp-vmess", vmess_in.tag);
    try std.testing.expectEqual(@as(u16, 19002), vmess_in.port);
    try std.testing.expectEqual(@as(usize, 1), vmess_in.vmess_users.len);
    try std.testing.expect(vmess_in.stream != null);
    try std.testing.expectEqualStrings("mkcp", vmess_in.stream.?.protocol_name);
    try std.testing.expectEqual(@as(u32, 1250), vmess_in.stream.?.kcp.?.mtu);

    const ob = rt.outbounds[0];
    try std.testing.expectEqualStrings("direct", ob.tag);
    try std.testing.expectEqualStrings("freedom", ob.protocol);
    try std.testing.expectEqual(@as(usize, 1), ob.freedom_rules.len);
    try std.testing.expectEqual(@import("freedom.zig").RuleAction.allow, ob.freedom_rules[0].action);
}

test "build runtime: unsupported inbound protocol exits" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var lg = log.Logger{ .enabled = false };
    var diag = Diag{};
    const cfg_json =
        \\{"inbounds":[{"tag":"x","listen":"0.0.0.0","port":1,"protocol":"trojan"}],
        \\ "outbounds":[{"protocol":"freedom","tag":"direct"}]}
    ;
    const root = try parseRoot(arena, cfg_json);
    try std.testing.expectError(ConfigError.UnsupportedInboundProtocol, buildRuntime(arena, &lg, &root, &diag));
}

test "build runtime: domain listen rejected" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var lg = log.Logger{ .enabled = false };
    var diag = Diag{};
    const cfg_json =
        \\{"inbounds":[{"tag":"x","listen":"bad.example.com","port":1,"protocol":"vless","settings":{"decryption":"none","clients":[]}}],
        \\ "outbounds":[{"protocol":"freedom","tag":"direct"}]}
    ;
    const root = try parseRoot(arena, cfg_json);
    try std.testing.expectError(ConfigError.InvalidListen, buildRuntime(arena, &lg, &root, &diag));
}

test "build runtime: vless decryption not none rejected" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var lg = log.Logger{ .enabled = false };
    var diag = Diag{};
    const cfg_json =
        \\{"inbounds":[{"tag":"x","listen":"0.0.0.0","port":1,"protocol":"vless","settings":{"decryption":"auto","clients":[]}}],
        \\ "outbounds":[{"protocol":"freedom","tag":"direct"}]}
    ;
    const root = try parseRoot(arena, cfg_json);
    try std.testing.expectError(ConfigError.Vless, buildRuntime(arena, &lg, &root, &diag));
    try std.testing.expect(std.mem.indexOf(u8, diag.message(), "decryption") != null);
}

test "build runtime: kcp validation error surfaces" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var lg = log.Logger{ .enabled = false };
    var diag = Diag{};
    const cfg_json =
        \\{"inbounds":[{"tag":"x","listen":"0.0.0.0","port":1,"protocol":"vmess","settings":{"clients":[]},
        \\  "streamSettings":{"network":"kcp","kcpSettings":{"mtu":20}}}],
        \\ "outbounds":[{"protocol":"freedom","tag":"direct"}]}
    ;
    const root = try parseRoot(arena, cfg_json);
    try std.testing.expectError(ConfigError.Transport, buildRuntime(arena, &lg, &root, &diag));
    try std.testing.expect(std.mem.indexOf(u8, diag.message(), "MTU must be at least 21") != null);
}

test "build runtime: localhost listen maps to 127.0.0.1" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var lg = log.Logger{ .enabled = false };
    var diag = Diag{};
    const cfg_json =
        \\{"inbounds":[{"tag":"x","listen":"localhost","port":19003,"protocol":"vless","settings":{"decryption":"none","clients":[]}}],
        \\ "outbounds":[{"protocol":"freedom","tag":"direct"}]}
    ;
    const root = try parseRoot(arena, cfg_json);
    const rt = try buildRuntime(arena, &lg, &root, &diag);
    try std.testing.expectEqual([4]u8{ 127, 0, 0, 1 }, rt.inbounds[0].listen.ipv4);
}
