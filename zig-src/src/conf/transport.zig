//! 传输层配置（上游 infra/conf/transport_internet.go + transport_method.go:618-658
//! + transport/internet/kcp/config.go 默认值，逐语义移植）。

const std = @import("std");
const log = @import("../app/log.zig");

pub const ConfigBuildError = error{
    UnknownTransportProtocol,
    RemovedTransportFeature,
    UnsupportedSecurity,
    KcpMtuTooSmall,
    KcpTtiOutOfRange,
    KcpCwndTooSmall,
    KcpSendingWindowTooSmall,
    BadPath,
    OutOfMemory,
};

/// TransportProtocol.Build：别名归一 + 弃用/移除警告（逐字对齐上游）
pub fn normalizeNetwork(logger: *log.Logger, network: []const u8, out: *[]const u8) ConfigBuildError!void {
    var buf: [32]u8 = undefined;
    if (network.len > buf.len) return ConfigBuildError.UnknownTransportProtocol;
    for (network, 0..) |c, i| buf[i] = std.ascii.toLower(c);
    const p = buf[0..network.len];
    if (std.mem.eql(u8, p, "raw") or std.mem.eql(u8, p, "tcp")) {
        out.* = "tcp";
        return;
    }
    if (std.mem.eql(u8, p, "kcp") or std.mem.eql(u8, p, "mkcp")) {
        out.* = "mkcp";
        return;
    }
    if (std.mem.eql(u8, p, "ws") or std.mem.eql(u8, p, "websocket")) {
        // PrintNonRemovalDeprecatedFeatureWarning("WebSocket transport (with ALPN http/1.1, etc.)", "XHTTP H2 & H3")
        logger.warning("DEPRECATED: WebSocket transport (with ALPN http/1.1, etc.) would be removed in the future, please use XHTTP H2 & H3 instead.");
        out.* = "websocket";
        return;
    }
    if (std.mem.eql(u8, p, "httpupgrade")) {
        logger.warning("DEPRECATED: HTTPUpgrade transport (with ALPN http/1.1, etc.) would be removed in the future, please use XHTTP H2 & H3 instead.");
        out.* = "httpupgrade";
        return;
    }
    if (std.mem.eql(u8, p, "h2") or std.mem.eql(u8, p, "h3") or std.mem.eql(u8, p, "http")) {
        logger.err("REMOVED: HTTP transport (without header padding, etc.) has been removed in this version, please use XHTTP stream-one H2 & H3 instead.");
        return ConfigBuildError.RemovedTransportFeature;
    }
    if (std.mem.eql(u8, p, "quic")) {
        logger.err("REMOVED: QUIC transport (without web service, etc.) has been removed in this version, please use XHTTP stream-one H3 instead.");
        return ConfigBuildError.RemovedTransportFeature;
    }
    return ConfigBuildError.UnknownTransportProtocol;
}

// ============================ WS ============================

pub const WebSocketConfig = struct {
    host: []const u8 = "",
    path: []const u8 = "",
    headers: ?std.json.Value = null,
    acceptProxyProtocol: bool = false,
    heartbeatPeriod: u32 = 0,

    pub const Built = struct {
        path: []const u8, // 已规范化（空→"/"，补前导斜杠）——对应上游 GetNormalizedPath
        host: []const u8,
        ed: u32,
        heartbeat_period: u32,
        early_data_headers: ?[]const u8 = null, // Sec-WebSocket-Protocol 回显名（本配置未用）
    };

    /// 对照 transport_method.go:618-658：
    /// path 里 ?ed=N 剥离入 Ed；headers 大小写不敏感 "host" 键迁移（host 空才生效）并打弃用警告
    pub fn build(self: *const WebSocketConfig, arena: std.mem.Allocator, logger: *log.Logger) ConfigBuildError!Built {
        var path = self.path;
        var ed: u32 = 0;
        if (std.mem.indexOfScalar(u8, path, '?')) |qi| {
            const query = path[qi + 1 ..];
            var it = std.mem.splitScalar(u8, query, '&');
            var kept: std.ArrayList(u8) = .empty;
            errdefer kept.deinit(arena);
            var first = true;
            var found_ed = false;
            while (it.next()) |kv| {
                if (kv.len == 0) continue;
                const eq = std.mem.indexOfScalar(u8, kv, '=') orelse continue;
                if (std.mem.eql(u8, kv[0..eq], "ed")) {
                    const v = kv[eq + 1 ..];
                    if (v.len > 0) {
                        const n = std.fmt.parseInt(u32, v, 10) catch 0;
                        if (n > 0) {
                            ed = n;
                            found_ed = true;
                        }
                    }
                    continue;
                }
                if (!first) kept.append(arena, '&') catch return ConfigBuildError.OutOfMemory;
                kept.appendSlice(arena, kv) catch return ConfigBuildError.OutOfMemory;
                first = false;
            }
            if (found_ed) {
                const base = path[0..qi];
                if (kept.items.len > 0) {
                    path = std.fmt.allocPrint(arena, "{s}?{s}", .{ base, kept.items }) catch return ConfigBuildError.OutOfMemory;
                } else {
                    path = base;
                }
            }
        }

        // headers 中大小写不敏感的 "host" 键迁移（对齐上游：就地 delete）
        var host = self.host;
        if (self.headers) |hv| {
            if (hv == .object) {
                const obj = @constCast(&self.headers.?.object);
                var to_delete: ?[]const u8 = null;
                var it = obj.iterator();
                while (it.next()) |e| {
                    const key = e.key_ptr.*;
                    if (key.len == 4 and std.ascii.eqlIgnoreCase(key, "host")) {
                        logger.warning("DEPRECATED: \"host\" in \"headers\" would be removed in the future, please use independent \"host\" instead.");
                        if (host.len == 0) {
                            if (e.value_ptr.* == .string) {
                                host = e.value_ptr.string;
                            }
                        }
                        to_delete = key;
                        break; // 上游 map 遍历迁移首个命中即可（delete 后 break）
                    }
                }
                if (to_delete) |k| _ = obj.orderedRemove(k);
            }
        }

        // Path 规范化（上游 transport/internet/websocket/config.go GetNormalizedPath）
        var norm = path;
        if (norm.len == 0) {
            norm = "/";
        } else if (norm[0] != '/') {
            norm = std.fmt.allocPrint(arena, "/{s}", .{norm}) catch return ConfigBuildError.OutOfMemory;
        }

        return .{ .path = norm, .host = host, .ed = ed, .heartbeat_period = self.heartbeatPeriod };
    }
};

// ============================ KCP ============================

/// 上游 transport/internet/kcp/config.go init() 默认值
pub const KcpDefaults = struct {
    pub const mtu: u32 = 1350;
    pub const tti: u32 = 50;
    pub const uplink_capacity: u32 = 5;
    pub const downlink_capacity: u32 = 20;
    pub const cwnd_multiplier: u32 = 1;
    pub const max_sending_window: u32 = 2 * 1024 * 1024;
};

pub const KcpConfig = struct {
    mtu: ?u32 = null,
    tti: ?u32 = null,
    uplinkCapacity: ?u32 = null,
    downlinkCapacity: ?u32 = null,
    cwndMultiplier: ?u32 = null,
    maxSendingWindow: ?u32 = null,
    // 上游可解析但 Build 静默忽略（PR #5560 已删除整层）
    header: ?std.json.Value = null,
    seed: ?[]const u8 = null,

    pub const Built = struct {
        mtu: u32,
        tti: u32,
        uplink_capacity: u32,
        downlink_capacity: u32,
        cwnd_multiplier: u32,
        max_sending_window: u32,
        sending_in_flight_size: u32,
        receiving_in_flight_size: u32,
        sending_buffer_size: u32, // 段数 = maxSendingWindow / mtu

        pub fn mss(self: Built) u32 {
            return self.mtu - 18;
        }
    };

    /// KCPConfig.Build：默认值填充 → 校验 → 派生量
    pub fn build(self: *const KcpConfig) ConfigBuildError!Built {
        var cfg = Built{
            .mtu = KcpDefaults.mtu,
            .tti = KcpDefaults.tti,
            .uplink_capacity = KcpDefaults.uplink_capacity,
            .downlink_capacity = KcpDefaults.downlink_capacity,
            .cwnd_multiplier = KcpDefaults.cwnd_multiplier,
            .max_sending_window = KcpDefaults.max_sending_window,
            .sending_in_flight_size = 0,
            .receiving_in_flight_size = 0,
            .sending_buffer_size = 0,
        };
        if (self.mtu) |v| cfg.mtu = v;
        if (self.tti) |v| cfg.tti = v;
        if (self.uplinkCapacity) |v| cfg.uplink_capacity = v;
        if (self.downlinkCapacity) |v| cfg.downlink_capacity = v;
        if (self.cwndMultiplier) |v| cfg.cwnd_multiplier = v;
        if (self.maxSendingWindow) |v| cfg.max_sending_window = v;

        // 校验（错误文案逐字对齐上游）
        if (cfg.mtu < 21) return ConfigBuildError.KcpMtuTooSmall;
        if (cfg.tti < 10 or cfg.tti > 1000) return ConfigBuildError.KcpTtiOutOfRange;
        if (cfg.cwnd_multiplier < 1) return ConfigBuildError.KcpCwndTooSmall;
        if (cfg.max_sending_window / cfg.mtu == 0) return ConfigBuildError.KcpSendingWindowTooSmall;

        // 派生量（对照 config.go GetSendingInFlightSize/GetReceivingInFlightSize/GetSendingBufferSize）
        const tti_div: u32 = 1000 / cfg.tti;
        if (tti_div == 0) return ConfigBuildError.KcpTtiOutOfRange;
        cfg.sending_in_flight_size = inFlight(cfg.uplink_capacity, cfg.mtu, tti_div);
        cfg.receiving_in_flight_size = inFlight(cfg.downlink_capacity, cfg.mtu, tti_div);
        cfg.sending_buffer_size = cfg.max_sending_window / cfg.mtu;
        return cfg;
    }

    fn inFlight(capacity_mib: u32, mtu: u32, tti_div: u32) u32 {
        var size: u64 = @as(u64, capacity_mib) * 1024 * 1024 / mtu / tti_div;
        if (size < 8) size = 8;
        return @intCast(size);
    }
};

// ============================ Stream ============================

pub const StreamConfig = struct {
    address: ?[]const u8 = null,
    port: u16 = 0,
    method: ?[]const u8 = null,
    network: ?[]const u8 = null,
    security: []const u8 = "none",
    tlsSettings: ?std.json.Value = null,
    realitySettings: ?std.json.Value = null,
    kcpSettings: ?KcpConfig = null,
    wsSettings: ?WebSocketConfig = null,
    sockopt: ?std.json.Value = null,

    pub const Built = struct {
        protocol_name: []const u8, // 归一化后（tcp/mkcp/websocket）
        security: []const u8, // "none"
        kcp: ?KcpConfig.Built = null,
        ws: ?WebSocketConfig.Built = null,
        listen_addr: ?[]const u8 = null, // stream 层 address（本配置未用）
        port: u16 = 0,
    };

    pub fn build(self: *const StreamConfig, arena: std.mem.Allocator, logger: *log.Logger) ConfigBuildError!Built {
        var protocol: []const u8 = "tcp";
        if (self.method) |m| {
            try normalizeNetwork(logger, m, &protocol);
        }
        if (self.network) |n| {
            try normalizeNetwork(logger, n, &protocol);
        }

        // security：Phase 1 只接受 ""/none（其余上游会走 TLS/REALITY 分支）
        var sec_buf: [16]u8 = undefined;
        const sec_lower: []const u8 = if (self.security.len <= sec_buf.len) blk: {
            for (self.security, 0..) |c, i| sec_buf[i] = std.ascii.toLower(c);
            break :blk sec_buf[0..self.security.len];
        } else self.security;
        if (sec_lower.len != 0 and !std.mem.eql(u8, sec_lower, "none")) {
            return ConfigBuildError.UnsupportedSecurity;
        }

        // acceptProxyProtocol 显式报错（表 1-2）
        if (self.sockopt) |so| {
            if (so == .object) {
                if (so.object.get("acceptProxyProtocol")) |v| {
                    if (v == .bool and v.bool) {
                        logger.err("PROXY protocol is not supported in this build.");
                        return ConfigBuildError.UnsupportedSecurity;
                    }
                }
            }
        }

        var built = Built{ .protocol_name = protocol, .security = sec_lower, .port = self.port };

        if (std.mem.eql(u8, protocol, "mkcp")) {
            const kc = self.kcpSettings orelse KcpConfig{};
            built.kcp = try kc.build();
        } else if (std.mem.eql(u8, protocol, "websocket")) {
            const wc = self.wsSettings orelse WebSocketConfig{};
            built.ws = try wc.build(arena, logger);
        }
        return built;
    }
};

// ============================ Sniffing ============================

pub const SniffingConfig = struct {
    enabled: bool = false,
    destOverride: []const []const u8 = &.{},
    routeOnly: bool = false,

    pub const Error = error{UnknownSniffingType};

    /// destOverride 枚举校验（enabled=false 也校验，对齐上游 Build 行为）
    pub fn validate(self: *const SniffingConfig) SniffingConfig.Error!void {
        for (self.destOverride) |d| {
            if (std.mem.eql(u8, d, "http") or std.mem.eql(u8, d, "tls") or
                std.mem.eql(u8, d, "quic") or std.mem.eql(u8, d, "fakedns") or
                std.mem.eql(u8, d, "fakedns+others"))
            {
                continue;
            }
            return SniffingConfig.Error.UnknownSniffingType;
        }
    }
};

test "network normalization aliases + deprecation" {
    var lg = log.Logger{ .enabled = false };
    var out: []const u8 = "";
    try normalizeNetwork(&lg, "raw", &out);
    try std.testing.expectEqualStrings("tcp", out);
    try normalizeNetwork(&lg, "kcp", &out);
    try std.testing.expectEqualStrings("mkcp", out);
    try normalizeNetwork(&lg, "mkcp", &out);
    try std.testing.expectEqualStrings("mkcp", out);
    try normalizeNetwork(&lg, "ws", &out);
    try std.testing.expectEqualStrings("websocket", out);
    try normalizeNetwork(&lg, "WebSocket", &out);
    try std.testing.expectEqualStrings("websocket", out);
    try std.testing.expectError(ConfigBuildError.RemovedTransportFeature, normalizeNetwork(&lg, "h2", &out));
    try std.testing.expectError(ConfigBuildError.RemovedTransportFeature, normalizeNetwork(&lg, "quic", &out));
    try std.testing.expectError(ConfigBuildError.UnknownTransportProtocol, normalizeNetwork(&lg, "grpc9", &out));
}

test "kcp defaults and derived sizes" {
    const kc = KcpConfig{};
    const b = try kc.build();
    try std.testing.expectEqual(@as(u32, 1350), b.mtu);
    try std.testing.expectEqual(@as(u32, 50), b.tti);
    try std.testing.expectEqual(@as(u32, 5), b.uplink_capacity);
    try std.testing.expectEqual(@as(u32, 20), b.downlink_capacity);
    try std.testing.expectEqual(@as(u32, 1), b.cwnd_multiplier);
    try std.testing.expectEqual(@as(u32, 2 * 1024 * 1024), b.max_sending_window);
    // xray.json 实际配置值：mtu1250/tti20/双向20 → InFlight=335, buffer=1677
    const kc2 = KcpConfig{ .mtu = 1250, .tti = 20, .uplinkCapacity = 20, .downlinkCapacity = 20 };
    const b2 = try kc2.build();
    try std.testing.expectEqual(@as(u32, 335), b2.sending_in_flight_size);
    try std.testing.expectEqual(@as(u32, 335), b2.receiving_in_flight_size);
    try std.testing.expectEqual(@as(u32, 1677), b2.sending_buffer_size);
    try std.testing.expectEqual(@as(u32, 1232), b2.mss());
}

test "kcp validation errors (upstream messages)" {
    // MTU must be at least 21
    try std.testing.expectError(ConfigBuildError.KcpMtuTooSmall, (KcpConfig{ .mtu = 20 }).build());
    // TTI must be between 10 and 1000
    try std.testing.expectError(ConfigBuildError.KcpTtiOutOfRange, (KcpConfig{ .tti = 9 }).build());
    try std.testing.expectError(ConfigBuildError.KcpTtiOutOfRange, (KcpConfig{ .tti = 1001 }).build());
    // CwndMultiplier must be at least 1
    try std.testing.expectError(ConfigBuildError.KcpCwndTooSmall, (KcpConfig{ .cwndMultiplier = 0 }).build());
    // MaxSendingWindow must be at least mtu（GetSendingBufferSize()==0，不要求整除）
    try std.testing.expectError(ConfigBuildError.KcpSendingWindowTooSmall, (KcpConfig{ .maxSendingWindow = 1000, .mtu = 1250 }).build());
    // 非整除但 >= mtu 合法（评审 P2-2：2MiB/1300 类配置不得拒绝）
    _ = try (KcpConfig{ .maxSendingWindow = 2 * 1024 * 1024, .mtu = 1300 }).build();
}

test "ws build: ed strip + host migration + path normalize" {
    var lg = log.Logger{ .enabled = false };
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    // host 迁移 + ed 剥离
    var headers = try std.json.ObjectMap.init(arena, &.{}, &.{});
    try headers.put(arena, "Host", .{ .string = "ltetp.tv189.com" });
    try headers.put(arena, "X-Custom", .{ .string = "v1" });
    const wc = WebSocketConfig{
        .host = "",
        .path = "/free?ed=2048",
        .headers = .{ .object = headers },
    };
    const b = try wc.build(arena, &lg);
    try std.testing.expectEqualStrings("/free", b.path);
    try std.testing.expectEqualStrings("ltetp.tv189.com", b.host);
    try std.testing.expectEqual(@as(u32, 2048), b.ed);
    // X-Custom 保留
    try std.testing.expectEqual(@as(u32, 1), wc.headers.?.object.count());

    // host 已配置时不迁移
    const wc2 = WebSocketConfig{ .host = "aaa.example.com", .path = "", .headers = .{ .object = headers } };
    const b2 = try wc2.build(arena, &lg);
    try std.testing.expectEqualStrings("aaa.example.com", b2.host);
    try std.testing.expectEqualStrings("/", b2.path);
}

test "sniffing enum validation even when disabled" {
    const s1 = SniffingConfig{ .enabled = false, .destOverride = &.{ "http", "tls", "quic", "fakedns" } };
    try s1.validate();
    const s2 = SniffingConfig{ .enabled = false, .destOverride = &.{"bogus"} };
    try std.testing.expectError(SniffingConfig.Error.UnknownSniffingType, s2.validate());
}

test "stream build for xray.json shapes" {
    var lg = log.Logger{ .enabled = false };
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const ws_stream = StreamConfig{
        .network = "ws",
        .security = "none",
        .wsSettings = .{ .path = "/free", .host = "", .headers = .{ .string = "ignored" } },
    };
    // headers 非 object → 迁移跳过
    const b1 = try ws_stream.build(arena, &lg);
    try std.testing.expectEqualStrings("websocket", b1.protocol_name);

    const kcp_stream = StreamConfig{
        .network = "kcp",
        .security = "none",
        .kcpSettings = .{ .mtu = 1250, .tti = 20, .uplinkCapacity = 20, .downlinkCapacity = 20 },
    };
    const b2 = try kcp_stream.build(arena, &lg);
    try std.testing.expectEqualStrings("mkcp", b2.protocol_name);
    try std.testing.expect(b2.kcp != null);
    try std.testing.expectEqual(@as(u32, 335), b2.kcp.?.sending_in_flight_size);

    // security 非 none 显式报错
    const tls_stream = StreamConfig{ .network = "ws", .security = "tls" };
    try std.testing.expectError(ConfigBuildError.UnsupportedSecurity, tls_stream.build(arena, &lg));
}
