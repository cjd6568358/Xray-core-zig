//! app/dispatcher + outbound_manager（§5.5；对照 app/dispatcher/default.go）。
//!
//! 本配置路径上 DefaultDispatcher 退化为「直接 routedDispatch」（sniffing 关闭、
//! 无路由规则）：取默认出站（outbounds 顺序第一个注册者 = freedom "direct"）
//! → 调 freedom.process。Router 接口位预留（Phase 1 恒走默认出站，等价
//! PickRoute 返回 ErrNoClue）；Go 的 mux.Server 在本配置是纯透传壳，Zig 不引入。
//!
//! access 日志（common/log AccessMessage.String 形态）：
//!   from {source} accepted {dest} [{inTag} >> {outTag}]

const std = @import("std");
const net = @import("../common/net.zig");
const stats_mod = @import("../app/stats.zig");
const buf = @import("../common/buf.zig");
const stream = @import("../core/stream.zig");
const applog = @import("../app/log.zig");
const conf = @import("../conf/config.zig");
const freedom = @import("../proxy/freedom.zig");

pub const OutboundHandler = struct {
    tag: []const u8,
    protocol: []const u8,
    freedom: ?*freedom.Handler = null, // Phase 1 唯一出站形态
};

pub const OutboundManager = struct {
    handlers: []const OutboundHandler = &.{},

    /// Go outbound.Manager.GetDefaultHandler：顺序第一个注册者（表 4-1）
    pub fn defaultHandler(self: *const OutboundManager) ?*const OutboundHandler {
        if (self.handlers.len == 0) return null;
        return &self.handlers[0];
    }

    /// Go outbound.Manager.GetHandler（路由命中 tag 查找；Phase 1 预留）
    pub fn getHandler(self: *const OutboundManager, tag: []const u8) ?*const OutboundHandler {
        for (self.handlers) |*h| {
            if (std.mem.eql(u8, h.tag, tag)) return h;
        }
        return null;
    }
};

pub const DispatchError = freedom.Handler.ProcessError;

pub const Dispatcher = struct {
    logger: *applog.Logger,
    outbounds: OutboundManager = .{},
    /// M15 统计（上游 app/dispatcher WrapLink）：null/默认关闭时零影响
    stats: ?*stats_mod.Manager = null,
    policy: conf.PolicyConfig = .{},

    /// 上游 ForLevel(user.Level).Stats.UserUplink/UserDownlink（按 email 找 user policy）
    fn userStatSwitch(policy: conf.PolicyConfig, email: []const u8) struct { bool, bool } {
        for (policy.user) |u| {
            if (std.mem.eql(u8, u.email, email)) return .{ u.statsUplink, u.statsDownlink };
        }
        return .{ false, false }; // 上游默认 false
    }

    /// Go routedDispatch：错误向上传（入站据此后决定是否写终止块/关连接）
    pub fn dispatch(
        self: *Dispatcher,
        arena: std.mem.Allocator,
        sess: *const buf.Session,
        dest: net.Destination,
        client: stream.Link,
    ) DispatchError!void {
        const handler = self.outbounds.defaultHandler() orelse {
            // Go routedDispatch: "default outbound handler not exist" → 关两侧
            self.logger.warning("default outbound handler not exist");
            return;
        };

        // access 记录（本配置落 /dev/null；形态对照 AccessMessage.String：from/status/to/[detour]/[email]）
        var dbuf: [96]u8 = undefined;
        const dn = dest.format(&dbuf);
        var list: std.ArrayList(u8) = .empty;
        if (std.fmt.allocPrint(arena, "from {s} accepted {s} [{s} >> {s}]", .{
            sess.getSource(), dbuf[0..dn], sess.inbound_tag, handler.tag,
        })) |head| {
            list.appendSlice(arena, head) catch {};
        } else |_| {}
        if (sess.user_email.len > 0) {
            if (std.fmt.allocPrint(arena, " email: {s}", .{sess.user_email})) |em| {
                list.appendSlice(arena, em) catch {};
            } else |_| {}
        }
        if (list.items.len > 0) self.logger.access(list.items);

        // M15：按 policy 开关取计数器（上游 WrapLink 语义：Reader→uplink、Writer→downlink）
        var cnt = stats_mod.Counters{};
        if (self.stats) |sm| {
            var nb: [128]u8 = undefined;
            if (self.policy.system.statsInboundUplink and sess.inbound_tag.len > 0) {
                cnt.inbound_up = sm.getOrRegisterCounter(stats_mod.inboundUpName(&nb, sess.inbound_tag));
            }
            if (self.policy.system.statsInboundDownlink and sess.inbound_tag.len > 0) {
                cnt.inbound_down = sm.getOrRegisterCounter(stats_mod.inboundDownName(&nb, sess.inbound_tag));
            }
            if (sess.user_email.len > 0) {
                const up_on, const down_on = userStatSwitch(self.policy, sess.user_email);
                if (up_on) cnt.user_up = sm.getOrRegisterCounter(stats_mod.userUpName(&nb, sess.user_email));
                if (down_on) cnt.user_down = sm.getOrRegisterCounter(stats_mod.userDownName(&nb, sess.user_email));
            }
        }

        if (handler.freedom) |f| {
            f.process(arena, sess, dest, client, if (cnt.any()) &cnt else null) catch |e| {
                var eb: [160]u8 = undefined;
                const em = std.fmt.bufPrint(&eb, "failed to process outbound traffic > {s}", .{@errorName(e)}) catch "failed to process outbound traffic";
                self.logger.warning(em);
                return e;
            };
        } else {
            self.logger.warning("unsupported outbound handler");
        }
    }
};

// ============================ 测试 ============================

const testecho = @import("../testing/echo.zig");
const sys = @import("../common/sys.zig");
const sock = @import("../common/sock.zig");
const conf_freedom = @import("../conf/freedom.zig");

const ProcArgs = struct {
    d: *Dispatcher,
    arena: std.mem.Allocator,
    sess: *const buf.Session,
    dest: net.Destination,
    client: stream.Link,
};

fn dispatchMain(a: *ProcArgs) void {
    a.d.dispatch(a.arena, a.sess, a.dest, a.client) catch {};
}

test "dispatch → 统计计数器（M15：policy 开启后按 channel 累加实际字节）" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var pool = buf.Pool.init(std.testing.allocator);
    defer pool.deinit();
    var lg = applog.Logger{ .enabled = false };
    var sm = stats_mod.Manager.init(std.testing.allocator);
    defer sm.deinit();

    const echo = try testecho.EchoServer.start();
    defer echo.stop();

    var sess = buf.Session{};
    sess.inbound_tag = "inbound-19001";
    sess.inbound_protocol = "vless";
    sess.user_email = "pb8lpgli";
    sess.setSource("127.0.0.1:40012");

    const allow = (conf_freedom.FinalRule{ .action = "allow" }).build(arena) catch unreachable;
    var fh = freedom.Handler{ .logger = &lg, .pool = &pool, .rules = &.{allow} };
    const handlers = [_]OutboundHandler{.{ .tag = "direct", .protocol = "freedom", .freedom = &fh }};
    // policy：inbound 与 user 两个维度的 uplink/downlink 全开（上游 channel 命名）
    var d = Dispatcher{
        .logger = &lg,
        .outbounds = .{ .handlers = handlers[0..] },
        .stats = &sm,
        .policy = .{
            .system = .{ .statsInboundUplink = true, .statsInboundDownlink = true },
            .user = &.{.{ .email = "pb8lpgli", .statsUplink = true, .statsDownlink = true }},
        },
    };

    var pair = try testecho.socketpairClient(arena);
    defer {
        pair.test_side.close();
        pair.deinit();
    }

    const dest = net.Destination{ .network = .tcp, .address = .{ .ipv4 = .{ 127, 0, 0, 1 } }, .port = echo.port() };
    var args = ProcArgs{ .d = &d, .arena = arena, .sess = &sess, .dest = dest, .client = pair.link() };
    const th = try std.Thread.spawn(.{ .stack_size = sys.crypto_thread_stack }, dispatchMain, .{&args});

    const payload = "0123456789"; // 10 字节
    try pair.test_side.writeAll(payload);
    var rb: [64]u8 = undefined;
    pair.test_side.setTimeout(5000);
    const n = try pair.test_side.read(&rb);
    try std.testing.expectEqualStrings(payload, rb[0..n]);
    pair.test_side.shutdownWrite();
    _ = pair.test_side.read(&rb) catch 0;
    th.join();

    // uplink = 客户端→服务端 10B；downlink = echo 回包 10B；两个维度各一对
    var nb: [128]u8 = undefined;
    try std.testing.expectEqual(@as(u64, payload.len), sm.getOrRegisterCounter(stats_mod.inboundUpName(&nb, "inbound-19001")).?.get());
    try std.testing.expectEqual(@as(u64, payload.len), sm.getOrRegisterCounter(stats_mod.inboundDownName(&nb, "inbound-19001")).?.get());
    try std.testing.expectEqual(@as(u64, payload.len), sm.getOrRegisterCounter(stats_mod.userUpName(&nb, "pb8lpgli")).?.get());
    try std.testing.expectEqual(@as(u64, payload.len), sm.getOrRegisterCounter(stats_mod.userDownName(&nb, "pb8lpgli")).?.get());
}

test "dispatch → 统计默认关闭时不注册任何 channel（M15：零影响）" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var pool = buf.Pool.init(std.testing.allocator);
    defer pool.deinit();
    var lg = applog.Logger{ .enabled = false };
    var sm = stats_mod.Manager.init(std.testing.allocator);
    defer sm.deinit();

    const echo = try testecho.EchoServer.start();
    defer echo.stop();

    var sess = buf.Session{};
    sess.inbound_tag = "inbound-19001";
    sess.inbound_protocol = "vless";
    sess.user_email = "pb8lpgli";
    sess.setSource("127.0.0.1:40013");

    const allow = (conf_freedom.FinalRule{ .action = "allow" }).build(arena) catch unreachable;
    var fh = freedom.Handler{ .logger = &lg, .pool = &pool, .rules = &.{allow} };
    const handlers = [_]OutboundHandler{.{ .tag = "direct", .protocol = "freedom", .freedom = &fh }};
    var d = Dispatcher{ .logger = &lg, .outbounds = .{ .handlers = handlers[0..] }, .stats = &sm };

    var pair = try testecho.socketpairClient(arena);
    defer {
        pair.test_side.close();
        pair.deinit();
    }

    const dest = net.Destination{ .network = .tcp, .address = .{ .ipv4 = .{ 127, 0, 0, 1 } }, .port = echo.port() };
    var args = ProcArgs{ .d = &d, .arena = arena, .sess = &sess, .dest = dest, .client = pair.link() };
    const th = try std.Thread.spawn(.{ .stack_size = sys.crypto_thread_stack }, dispatchMain, .{&args});

    try pair.test_side.writeAll("no stats");
    var rb: [64]u8 = undefined;
    pair.test_side.setTimeout(5000);
    _ = try pair.test_side.read(&rb);
    pair.test_side.shutdownWrite();
    _ = pair.test_side.read(&rb) catch 0;
    th.join();

    const snap = try sm.snapshot(std.testing.allocator);
    defer std.testing.allocator.free(snap);
    try std.testing.expectEqual(@as(usize, 0), snap.len); // 全关 → 一个 channel 都没有
}

test "dispatch → freedom → echo 全链（默认出站 + access 落点）" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var pool = buf.Pool.init(std.testing.allocator);
    defer pool.deinit();
    var lg = applog.Logger{ .enabled = false };

    const echo = try testecho.EchoServer.start();
    defer echo.stop();

    var sess = buf.Session{};
    sess.inbound_tag = "inbound-19001";
    sess.inbound_protocol = "vless";
    sess.setSource("127.0.0.1:40011");

    const allow = (conf_freedom.FinalRule{ .action = "allow" }).build(arena) catch unreachable;
    var fh = freedom.Handler{ .logger = &lg, .pool = &pool, .rules = &.{allow} };
    const handlers = [_]OutboundHandler{.{ .tag = "direct", .protocol = "freedom", .freedom = &fh }};
    var d = Dispatcher{ .logger = &lg, .outbounds = .{ .handlers = handlers[0..] } };

    var pair = try testecho.socketpairClient(arena);
    defer {
        pair.test_side.close();
        pair.deinit();
    }

    const dest = net.Destination{ .network = .tcp, .address = .{ .ipv4 = .{ 127, 0, 0, 1 } }, .port = echo.port() };
    var args = ProcArgs{ .d = &d, .arena = arena, .sess = &sess, .dest = dest, .client = pair.link() };
    const th = try std.Thread.spawn(.{ .stack_size = sys.crypto_thread_stack }, dispatchMain, .{&args});

    try pair.test_side.writeAll("via dispatcher");
    var rb: [64]u8 = undefined;
    pair.test_side.setTimeout(5000);
    const n = try pair.test_side.read(&rb);
    try std.testing.expectEqualStrings("via dispatcher", rb[0..n]);
    pair.test_side.shutdownWrite();
    const n2 = pair.test_side.read(&rb) catch 0;
    try std.testing.expectEqual(@as(usize, 0), n2);
    th.join();
}

test "outbound manager: default = 顺序第一个；getHandler 按 tag" {
    const handlers = [_]OutboundHandler{
        .{ .tag = "direct", .protocol = "freedom" },
        .{ .tag = "second", .protocol = "freedom" },
    };
    const om = OutboundManager{ .handlers = handlers[0..] };
    try std.testing.expectEqualStrings("direct", om.defaultHandler().?.tag);
    try std.testing.expect(om.getHandler("second") != null);
    try std.testing.expect(om.getHandler("nope") == null);

    const empty = OutboundManager{};
    try std.testing.expect(empty.defaultHandler() == null);
}
