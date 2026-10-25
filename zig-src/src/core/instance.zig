//! core.Instance（§5.2；对应 Go core.Instance + proxyman 的最小子集）。
//!
//! 启动顺序（对齐上游）：log 先就绪（调用方持有）→ 创建出站（freedom 注册为
//! 默认）→ 创建入站（各自开监听线程）→ 打印启动日志。
//! 关闭顺序反演：先停 accept（shutdown 监听 socket 唤醒阻塞 accept）→ 等
//! 连接收敛 → 释放资源。SIGINT/SIGTERM 置位由主循环轮询（handler 内零分配零 IO）。
//!
//! M3 边界：入站协议处理器在 M4/M5/M7 落地，此阶段 accept 后即关（监听面可验）；
//! mkcp 入站监听（UDP 会话）M6 落地，此前打告警跳过。

const std = @import("std");
const linux = std.os.linux;
const sys = @import("../common/sys.zig");
const sock = @import("../common/sock.zig");
const buf = @import("../common/buf.zig");
const stream_mod = @import("../core/stream.zig");
const applog = @import("../app/log.zig");
const conf = @import("../conf/config.zig");
const disp = @import("../app/dispatcher.zig");
const freedom = @import("../proxy/freedom.zig");
const wssrv = @import("../transport/websocket/server.zig");
const vless_inbound = @import("../proxy/vless/inbound.zig");
const kcp_listener = @import("../transport/kcp/listener.zig");
const vmess_inbound = @import("../proxy/vmess/inbound.zig");
const stats_mod = @import("../app/stats.zig");
const vmess_replay = @import("../proxy/vmess/replay.zig");
const selfcheck = @import("../app/selfcheck.zig");

pub const Instance = struct {
    gpa: std.mem.Allocator,
    cfg: *const conf.RuntimeConfig,
    logger: *applog.Logger,
    version: []const u8,
    pool: buf.Pool,
    freedom_handler: freedom.Handler = undefined,
    outbounds_storage: [1]disp.OutboundHandler = .{.{ .tag = "", .protocol = "" }},
    has_outbound: bool = false,
    dispatcher: disp.Dispatcher = undefined,
    listeners: std.ArrayList(ListenerEntry) = .empty,
    kcp_listeners: std.ArrayList(*kcp_listener.Listener) = .empty,
    vmess_filter: ?*vmess_replay.ReplayFilter = null,
    vmess_history: ?*vmess_replay.SessionHistory = null,
    /// M15 流量统计（上游 features/stats Manager）：开关全关时也存在但无 channel
    stats_manager: ?*stats_mod.Manager = null,
    running: std.atomic.Value(bool) = .init(false),
    active_conns: std.atomic.Value(u32) = .init(0),
    /// §3.5 并发上限（默认 64，可调）：超限新连接直接关闭并记 overload 日志
    max_conns: u32 = buf.Policy.max_concurrent_conns,
    /// §7.4 自检日志周期（ms；0 = 关闭）
    selfcheck_interval_ms: u32 = buf.Policy.selfcheck_interval_ms,
    selfcheck_thread: ?std.Thread = null,
    stopped: bool = false,

    pub fn create(
        gpa: std.mem.Allocator,
        cfg: *const conf.RuntimeConfig,
        logger: *applog.Logger,
        version: []const u8,
    ) std.mem.Allocator.Error!*Instance {
        const self = try gpa.create(Instance);
        self.* = .{ .gpa = gpa, .cfg = cfg, .logger = logger, .version = version, .pool = buf.Pool.init(gpa) };
        self.vmess_filter = vmess_replay.ReplayFilter.create(gpa) catch null;
        self.vmess_history = vmess_replay.SessionHistory.create(gpa) catch null;
        // M15：统计 Manager 始终创建（channel 按需注册；开关全关则永远为空）
        if (gpa.create(stats_mod.Manager)) |sm| {
            sm.* = stats_mod.Manager.init(gpa);
            self.stats_manager = sm;
        } else |_| {}

        // 出站：默认出站 = outbounds 顺序第一个（表 4-1；conf 层保证非空）
        if (cfg.outbounds.len > 0) {
            const ob = &cfg.outbounds[cfg.default_outbound];
            self.freedom_handler = .{ .logger = logger, .pool = &self.pool, .rules = ob.freedom_rules };
            self.outbounds_storage[0] = .{ .tag = ob.tag, .protocol = ob.protocol, .freedom = &self.freedom_handler };
            self.dispatcher = .{ .logger = logger, .outbounds = .{ .handlers = self.outbounds_storage[0..] }, .stats = self.stats_manager, .policy = cfg.policy };
            self.has_outbound = true;
        }
        return self;
    }

    pub fn start(self: *Instance) !void {
        sock.ignoreSigpipe();
        self.running.store(true, .release);
        // 预分配（后续 append 不搬移 → 线程持有的 entry 指针稳定）
        try self.listeners.ensureTotalCapacity(self.gpa, self.cfg.inbounds.len);

        for (self.cfg.inbounds) |*ib| {
            const network: []const u8 = if (ib.stream) |s| s.protocol_name else "tcp";
            if (std.mem.eql(u8, network, "mkcp")) {
                // M6：UDP 会话面（协议面 VMess 在 M7 接管）
                const kc = ib.stream.?.kcp orelse return error.BadKcpConfig;
                const kcfg = kcp_listener.Config{
                    .mtu = kc.mtu,
                    .tti = kc.tti,
                    .cwnd_multiplier = kc.cwnd_multiplier,
                    .sending_in_flight = kc.sending_in_flight_size,
                    .receiving_in_flight = kc.receiving_in_flight_size,
                    .sending_buffer_size = kc.sending_buffer_size,
                };
                const listen4 = switch (ib.listen) {
                    .ipv4 => |b4| b4,
                    else => return error.UnsupportedListenFamily,
                };
                const actx = try self.gpa.create(KcpAddConnCtx);
                actx.* = .{ .instance = self, .tag = ib.tag, .ib = ib };
                const kl = kcp_listener.Listener.create(self.gpa, self.logger, listen4, ib.port, kcfg, .{ .ctx = actx, .fn_ = KcpAddConnCtx.onConn }) catch |e| {
                    self.gpa.destroy(actx);
                    return e;
                };
                self.kcp_listeners.append(self.gpa, kl) catch return error.OutOfMemory;
                continue;
            }
            // TCP 家族（tcp/websocket）：accept 面即 TCP 监听
            const listen4 = switch (ib.listen) {
                .ipv4 => |b4| b4,
                else => return error.UnsupportedListenFamily,
            };
            const l = try sock.TcpListener.bind(listen4, ib.port, 128);
            self.listeners.appendAssumeCapacity(.{ .inbound_tag = ib.tag, .listener = l, .thread = null, .ib = ib });
            const entry = &self.listeners.items[self.listeners.items.len - 1];
            entry.thread = std.Thread.spawn(.{ .stack_size = sys.min_thread_stack }, acceptLoop, .{ self, entry }) catch |e| {
                l.close();
                return e;
            };
        }

        {
            var mb: [128]u8 = undefined;
            if (std.fmt.bufPrint(&mb, "XrayZ {s} started", .{self.version})) |m| {
                self.logger.info(m);
            } else |_| {}
        }
        // §7.4 自检线程（每 60s 一行；72h soak 资源曲线来源）
        if (self.selfcheck_interval_ms > 0) {
            // M15：stats Manager 透传给自检线程（随 selfcheck 行输出非零 channel）
            const stats_arg: ?*stats_mod.Manager = self.stats_manager;
            self.selfcheck_thread = std.Thread.spawn(.{ .stack_size = sys.min_thread_stack }, selfcheck.run, .{
                self.logger,
                &self.running,
                &self.active_conns,
                self.selfcheck_interval_ms,
                stats_arg,
            }) catch null;
        }
    }

    fn acceptLoop(self: *Instance, entry: *ListenerEntry) void {
        while (self.running.load(.acquire)) {
            const conn = (entry.listener.accept() catch return) orelse continue; // stop() → shutdown → 退出
            // 并发上限：max_conns == 0 表示不限（对齐上游默认行为）
            if (self.max_conns > 0 and self.active_conns.load(.acquire) >= self.max_conns) {
                var sb: [48]u8 = undefined;
                const sn = conn.peerAddr(sb[0..]);
                self.logOverload(if (sn > 0) sb[0..sn] else "unknown");
                conn.close();
                continue;
            }
            _ = self.active_conns.fetchAdd(1, .monotonic);
            // 协议 handler 线程：VMess 头 AEAD/KDF → crypto 栈
            const th = std.Thread.spawn(.{ .stack_size = sys.crypto_thread_stack }, connEntry, .{ self, entry, conn }) catch {
                _ = self.active_conns.fetchSub(1, .monotonic);
                conn.close();
                continue;
            };
            th.detach();
        }
    }

    /// §3.5 overload 日志（超并发上限被拒的连接）
    fn logOverload(self: *Instance, source: []const u8) void {
        var mb: [160]u8 = undefined;
        const msg = std.fmt.bufPrint(
            &mb,
            "rejecting connection from {s}: concurrent connections exceed limit {d} (active={d})",
            .{ source, self.max_conns, self.active_conns.load(.acquire) },
        ) catch return;
        self.logger.warning(msg);
    }

    fn connEntry(self: *Instance, entry: *ListenerEntry, conn: sock.TcpConn) void {
        defer _ = self.active_conns.fetchSub(1, .monotonic);
        defer conn.close();

        var src_buf: [48]u8 = undefined;
        const sn = conn.peerAddr(src_buf[0..]);
        const source = if (sn > 0) src_buf[0..sn] else "unknown";

        var arena_state = std.heap.ArenaAllocator.init(self.gpa);
        defer arena_state.deinit();
        const arena = arena_state.allocator();
        const ctx = arena.create(stream_mod.TcpStreamCtx) catch return;
        ctx.* = .{ .conn = conn };
        var sess_stream = ctx.stream();

        // M12 排障日志：连接生命周期（弱网下短命连接 = 客户端重连风暴的直接证据）
        const started_ms = sys.nowMonoMs();
        const network: []const u8 = if (entry.ib.stream) |s| s.protocol_name else "tcp";
        defer {
            var lb: [192]u8 = undefined;
            if (std.fmt.bufPrint(&lb, "connection closed: from={s} tag={s} transport={s} protocol={s} duration={d}ms", .{ source, entry.ib.tag, network, entry.ib.protocol, sys.nowMonoMs() - started_ms })) |m| {
                self.logger.info(m);
            } else |_| {}
        }

        // 传输面：websocket → 握手升级为 WS 会话；tcp → 裸流
        if (std.mem.eql(u8, network, "websocket")) {
            const w = if (entry.ib.stream.?.ws) |w| w else return;
            switch (wssrv.handshake(arena, sess_stream, .{ .host = w.host, .path = w.path })) {
                .ok => |ws| sess_stream = ws.stream(),
                .rejected => return, // 错误响应已写
                .dropped => {
                    // 弱网半包头/解析失败：原先静默，排障期必须留痕
                    var wb: [128]u8 = undefined;
                    if (std.fmt.bufPrint(&wb, "ws handshake dropped (read/parse failure) from {s}", .{source})) |m| {
                        self.logger.warning(m);
                    } else |_| {}
                    return;
                },
            }
        }

        // 协议面：vless（M5）/ vmess（M7）
        if (std.mem.eql(u8, entry.ib.protocol, "vless")) {
            vless_inbound.handle(arena, self.gpa, sess_stream, conn, entry.ib.vless_users, self.logger, &self.dispatcher, entry.ib.tag, source, entry.ib.vless_fallbacks);
        } else if (std.mem.eql(u8, entry.ib.protocol, "vmess")) {
            if (self.vmess_filter == null or self.vmess_history == null) return;
            vmess_inbound.handle(arena, self.gpa, sess_stream, entry.ib.vmess_users, self.vmess_filter.?, self.vmess_history.?, self.logger, &self.dispatcher, entry.ib.tag, source);
        }
    }

    /// 优雅退出（关闭顺序反演：先停 accept → 等连接收敛 → 释放资源）
    pub fn stop(self: *Instance) void {
        if (self.stopped) return;
        self.stopped = true;
        self.running.store(false, .release);
        // shutdown 监听 socket 唤醒阻塞 accept（Linux 上 close 不可靠唤醒）
        for (self.listeners.items) |*e| {
            _ = linux.shutdown(e.listener.fd, linux.SHUT.RDWR);
        }
        for (self.listeners.items) |*e| {
            if (e.thread) |t| t.join();
            e.listener.close();
        }
        self.listeners.deinit(self.gpa);
        self.listeners = .empty;
        // kcp 监听：先切断会话（强制终结 → 协议线程 EOF 退出），
        // 等协议线程收敛后再收割销毁（M9：单步 close 会在会话线程仍持 conn 时释放）
        for (self.kcp_listeners.items) |l| l.shutdown();
        var waited: u32 = 0;
        while (self.active_conns.load(.acquire) > 0 and waited < 3000) : (waited += 20) {
            sys.sleepMs(20);
        }
        for (self.kcp_listeners.items) |l| {
            const actx: *KcpAddConnCtx = @ptrCast(@alignCast(l.add_conn.ctx));
            l.deinit();
            self.gpa.destroy(actx);
        }
        self.kcp_listeners.deinit(self.gpa);
        self.kcp_listeners = .empty;
        // 自检线程（running 已置 false，200ms 内退出）
        if (self.selfcheck_thread) |t| {
            t.join();
            self.selfcheck_thread = null;
        }
        if (self.vmess_filter) |f| f.destroy();
        if (self.vmess_history) |h| h.destroy();
        if (self.stats_manager) |sm| {
            sm.deinit();
            self.gpa.destroy(sm);
        }
        // 连接线程 detached；等存量收敛（正常情况上面已收敛）
        waited = 0;
        while (self.active_conns.load(.acquire) > 0 and waited < 2000) : (waited += 20) {
            sys.sleepMs(20);
        }
        self.pool.deinit();
    }

    /// M7：kcp 新会话 → VMess 处理（独立线程；Go addConn → goroutine）
    const KcpAddConnCtx = struct {
        instance: *Instance,
        tag: []const u8,
        ib: *const conf.RuntimeInbound,

        const ThreadArgs = struct {
            instance: *Instance,
            conn: *kcp_listener.Connection,
            ib: *const conf.RuntimeInbound,
        };

        fn onConn(ctx: *anyopaque, conn: *kcp_listener.Connection) void {
            const self: *KcpAddConnCtx = @ptrCast(@alignCast(ctx));
            // 并发上限（UDP 会话面同规则；0 = 不限）
            if (self.instance.max_conns > 0 and self.instance.active_conns.load(.acquire) >= self.instance.max_conns) {
                var sb: [48]u8 = undefined;
                const sn = sock.formatV4(conn.peer, sb[0..]);
                self.instance.logOverload(if (sn > 0) sb[0..sn] else "kcp-session");
                conn.forceTerminate();
                return;
            }
            _ = self.instance.active_conns.fetchAdd(1, .monotonic);
            {
                // M12 排障：KCP 会话建立（弱网下观察会话建立速率/对端）
                var sb: [48]u8 = undefined;
                const sn = sock.formatV4(conn.peer, sb[0..]);
                var kb: [128]u8 = undefined;
                if (std.fmt.bufPrint(&kb, "kcp session opened: conv={d} from={s}", .{ conn.conv, if (sn > 0) sb[0..sn] else "unknown" })) |m| {
                    self.instance.logger.info(m);
                } else |_| {}
            }
            const ta = self.instance.gpa.create(ThreadArgs) catch {
                _ = self.instance.active_conns.fetchSub(1, .monotonic);
                conn.closeConn();
                return;
            };
            ta.* = .{ .instance = self.instance, .conn = conn, .ib = self.ib };
            // KCP 会话线程：VMess 头 + 分块体 → crypto 栈
            const th = std.Thread.spawn(.{ .stack_size = sys.crypto_thread_stack }, sessionMain, .{ta}) catch {
                self.instance.gpa.destroy(ta);
                _ = self.instance.active_conns.fetchSub(1, .monotonic);
                conn.closeConn();
                return;
            };
            th.detach();
        }

        fn sessionMain(ta: *ThreadArgs) void {
            // 注意 defer 求值顺序（LIFO）：先取局部快照，避免 destroy(ta) 后
            // 再解引用 ta.instance（M9 实机互通踩到的 use-after-free：进程在
            // 会话收尾时 SIGSEGV，表现为 1MiB 传输截断 + 后续连接全超时）
            const inst = ta.instance;
            const conn = ta.conn;
            // M12 排障：KCP 会话关闭（含存活时长，短命会话=弱网重连风暴证据）
            // ⚠️ conv 必须提前快照：defer 是 LIFO，本日志块在 conn.closeConn() **之后**
            // 才执行，此时 Connection 可能已被 Terminate 清理线程释放（实测 SIGSEGV）。
            const conn_conv = conn.conv;
            const started_ms = sys.nowMonoMs();
            // M28 复盘统计：sent/retrans/rto。⚠️ 与 conv 同理必须用变量快照——
            // 本 defer 块在 conn.closeConn() 之后才执行，且统计值必须在 closeConn
            // 之前从 Connection 取出（之后可能已被释放）。
            var kcp_sent: u32 = 0;
            var kcp_retrans: u32 = 0;
            var kcp_rto_ms: u32 = 0;
            defer {
                var kb: [128]u8 = undefined;
                if (std.fmt.bufPrint(&kb, "kcp session closed: conv={d} duration={d}ms sent={d} retrans={d} rto={d}ms", .{ conn_conv, sys.nowMonoMs() - started_ms, kcp_sent, kcp_retrans, kcp_rto_ms })) |m| {
                    inst.logger.info(m);
                } else |_| {}
            }
            defer _ = inst.active_conns.fetchSub(1, .monotonic);
            defer inst.gpa.destroy(ta);
            defer conn.closeConn();

            var arena_state = std.heap.ArenaAllocator.init(inst.gpa);
            defer arena_state.deinit();
            const arena = arena_state.allocator();

            // 会话流 = KCP Connection 的 Stream 实现
            const sess_stream = conn.stream();

            // access 日志来源：会话记录的对端地址（udp 会话无 TCP 五元组）
            var src_buf: [48]u8 = undefined;
            const sn = sock.formatV4(conn.peer, &src_buf);
            const source = if (sn > 0) src_buf[0..sn] else "kcp-session";

            if (std.mem.eql(u8, ta.ib.protocol, "vmess")) {
                if (inst.vmess_filter == null or inst.vmess_history == null) return;
                vmess_inbound.handle(arena, inst.gpa, sess_stream, ta.ib.vmess_users, inst.vmess_filter.?, inst.vmess_history.?, inst.logger, &inst.dispatcher, ta.ib.tag, source);
                // M28：dispatch 已返回、closeConn 尚未执行——此刻取发送统计
                // （retrans>0 = 会话期间发生过重传，即弱网丢包的直接证据）
                const st = conn.sendingStats();
                kcp_sent = st.sent;
                kcp_retrans = st.retrans;
                kcp_rto_ms = st.rto_ms;
            }
        }
    };

    pub fn destroy(self: *Instance) void {
        self.gpa.destroy(self);
    }
};

const ListenerEntry = struct {
    inbound_tag: []const u8,
    listener: sock.TcpListener,
    thread: ?std.Thread,
    ib: *const conf.RuntimeInbound,
};

// ============================ 信号处理 ============================

var g_sig_shutdown = std.atomic.Value(bool).init(false);

fn onShutdownSignal(_: linux.SIG) callconv(.c) void {
    g_sig_shutdown.store(true, .release);
}

/// SIGINT/SIGTERM：置退出位（无 SA_RESTART → 阻塞 syscall 返 EINTR 便于收尾）
pub fn installSignalHandlers() void {
    var act: linux.Sigaction = .{
        .handler = .{ .handler = &onShutdownSignal },
        .mask = linux.sigemptyset(),
        .flags = 0,
    };
    _ = linux.sigaction(.INT, &act, null);
    _ = linux.sigaction(.TERM, &act, null);
}

pub fn shutdownRequested() bool {
    return g_sig_shutdown.load(.acquire);
}

// ============================ 测试 ============================

test "instance: start → 端口监听可连 → stub 即关 → stop 优雅退出" {
    var lg = applog.Logger{ .enabled = false };
    const inbounds = [_]conf.RuntimeInbound{
        .{
            .tag = "t0",
            .listen = .{ .ipv4 = .{ 127, 0, 0, 1 } },
            .port = 0, // 临时端口
            .protocol = "vless",
            .sniffing_enabled = false,
            .stream = .{ .protocol_name = "tcp", .security = "none" },
        },
    };
    const outbounds = [_]conf.RuntimeOutbound{
        .{ .tag = "direct", .protocol = "freedom" },
    };
    const cfg = conf.RuntimeConfig{
        .log_level = .none,
        .access_path = "",
        .inbounds = inbounds[0..],
        .outbounds = outbounds[0..],
        .default_outbound = 0,
    };
    const inst = try Instance.create(std.testing.allocator, &cfg, &lg, "test");
    try inst.start();
    defer inst.destroy();

    try std.testing.expect(inst.has_outbound);
    try std.testing.expectEqualStrings("direct", inst.dispatcher.outbounds.defaultHandler().?.tag);

    const port = inst.listeners.items[0].listener.actualPort();
    try std.testing.expect(port > 0);

    // 连接被接受，stub 立即关闭 → 读到 EOF
    const sa = sys.SockaddrIn.init(.{ 127, 0, 0, 1 }, port);
    const conn = try sock.dialTcp(.{ .v4 = sa }, 2000);
    var rb: [16]u8 = undefined;
    conn.setTimeout(2000);
    const n = conn.read(&rb) catch 0;
    try std.testing.expectEqual(@as(usize, 0), n);
    conn.close();

    inst.stop();
    try std.testing.expectEqual(@as(u32, 0), inst.active_conns.load(.monotonic));

    // stop 后端口不再接受连接
    if (sock.dialTcp(.{ .v4 = sa }, 500)) |c| {
        c.close();
        return error.ListenerStillOpen;
    } else |_| {}
}

test "instance: mkcp 入站建立 UDP 监听（M6）" {
    var lg = applog.Logger{ .enabled = false };
    const inbounds = [_]conf.RuntimeInbound{
        .{
            .tag = "kcp",
            .listen = .{ .ipv4 = .{ 127, 0, 0, 1 } },
            .port = 0,
            .protocol = "vmess",
            .sniffing_enabled = false,
            .stream = .{
                .protocol_name = "mkcp",
                .security = "none",
                .kcp = .{
                    .mtu = 1350,
                    .tti = 50,
                    .uplink_capacity = 5,
                    .downlink_capacity = 20,
                    .cwnd_multiplier = 1,
                    .max_sending_window = 2097152,
                    .sending_in_flight_size = 8,
                    .receiving_in_flight_size = 8,
                    .sending_buffer_size = 1553,
                },
            },
        },
    };
    const outbounds = [_]conf.RuntimeOutbound{
        .{ .tag = "direct", .protocol = "freedom" },
    };
    const cfg = conf.RuntimeConfig{
        .log_level = .none,
        .access_path = "",
        .inbounds = inbounds[0..],
        .outbounds = outbounds[0..],
        .default_outbound = 0,
    };
    const inst = try Instance.create(std.testing.allocator, &cfg, &lg, "test");
    try inst.start();
    defer inst.destroy();
    try std.testing.expectEqual(@as(usize, 0), inst.listeners.items.len); // 无 TCP 监听
    try std.testing.expectEqual(@as(usize, 1), inst.kcp_listeners.items.len); // UDP 会话面已建
    inst.stop();
}

test "instance: ipv6 监听启动失败（Phase 1 v4-only）" {
    var lg = applog.Logger{ .enabled = false };
    const inbounds = [_]conf.RuntimeInbound{
        .{
            .tag = "x",
            .listen = .{ .ipv6 = @splat(1) },
            .port = 19099,
            .protocol = "vless",
            .sniffing_enabled = false,
            .stream = .{ .protocol_name = "tcp", .security = "none" },
        },
    };
    const outbounds = [_]conf.RuntimeOutbound{
        .{ .tag = "direct", .protocol = "freedom" },
    };
    const cfg = conf.RuntimeConfig{
        .log_level = .none,
        .access_path = "",
        .inbounds = inbounds[0..],
        .outbounds = outbounds[0..],
        .default_outbound = 0,
    };
    const inst = try Instance.create(std.testing.allocator, &cfg, &lg, "test");
    defer inst.destroy();
    try std.testing.expectError(error.UnsupportedListenFamily, inst.start());
    inst.stop();
}

test "instance: §3.5 并发上限——超限新连接被立即关闭" {
    var lg = applog.Logger{ .enabled = false };
    const inbounds = [_]conf.RuntimeInbound{
        .{
            .tag = "t0",
            .listen = .{ .ipv4 = .{ 127, 0, 0, 1 } },
            .port = 0,
            .protocol = "vless",
            .sniffing_enabled = false,
            .stream = .{ .protocol_name = "tcp", .security = "none" },
        },
    };
    const outbounds = [_]conf.RuntimeOutbound{
        .{ .tag = "direct", .protocol = "freedom" },
    };
    const cfg = conf.RuntimeConfig{
        .log_level = .none,
        .access_path = "",
        .inbounds = inbounds[0..],
        .outbounds = outbounds[0..],
        .default_outbound = 0,
    };
    const inst = try Instance.create(std.testing.allocator, &cfg, &lg, "test");
    inst.max_conns = 1;
    try inst.start();
    defer inst.destroy();

    const port = inst.listeners.items[0].listener.actualPort();
    const sa = sys.SockaddrIn.init(.{ 127, 0, 0, 1 }, port);

    // 第一条：不发 VLESS 头 → handler 阻塞在头读取，占住唯一配额
    const c1 = try sock.dialTcp(.{ .v4 = sa }, 2000);
    defer c1.close();
    var waited: u32 = 0;
    while (inst.active_conns.load(.acquire) < 1 and waited < 2000) : (waited += 10) sys.sleepMs(10);
    try std.testing.expectEqual(@as(u32, 1), inst.active_conns.load(.acquire));

    // 第二条：超限 → 服务端 accept 后立即关闭（读到 EOF）
    const c2 = try sock.dialTcp(.{ .v4 = sa }, 2000);
    defer c2.close();
    var rb: [16]u8 = undefined;
    c2.setTimeout(3000);
    const n = c2.read(&rb) catch 0;
    try std.testing.expectEqual(@as(usize, 0), n);
    try std.testing.expectEqual(@as(u32, 1), inst.active_conns.load(.acquire)); // 未占用配额

    c1.close();
    waited = 0;
    while (inst.active_conns.load(.acquire) > 0 and waited < 3000) : (waited += 10) sys.sleepMs(10);
    inst.stop();
}
