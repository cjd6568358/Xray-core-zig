//! freedom 直连出站（§5.6；对照 proxy/freedom/freedom.go @ v26.10.21）。
//!
//! 流程：finalRules 求值（用户规则按序取首条命中，未命中再求内置默认规则）
//!   → 拨号（16s 超时 + ExponentialBackoff(5,100) + Chrome keepalive 45s/45s）
//!   → 双向拷贝（8KB 池；ConnectionIdle 300s 判死；单向 EOF 后对向 1s 收尾）
//!   → block = 黑洞（上行全丢弃 + 随机延迟后断开）。
//!
//! 与上游的有意偏差（§4.4）：
//!   D1 —— 域名目标仅在「存在带 ip 匹配器的用户规则，或内置默认规则可达」时
//!         才做 DNS 预检（本配置 [{action:"allow"}] 无条件放行 → 恒跳过）；
//!   D3 —— 下行不用 splice，统一 8KB 用户态拷贝。
//!
//! 半关闭语义（对照 Go 管道模型）：
//!   客户端 EOF 不向远端传播（上游 freedom 无 CloseWrite）；远端 EOF → 客户端
//!   方向 shutdownWrite（对应 task.Close(output)）；任一方向出错 → shutdown
//!   远端以唤醒对侧拷贝线程。空闲判死用 1s 读超时切片实现（对应 Go 的
//!   inactivity timer cancel，判死粒度 ≤1s，阈值语义一致）。

const std = @import("std");
const linux = std.os.linux;
const sys = @import("../common/sys.zig");
const stats_mod = @import("../app/stats.zig");
const udp_pkt = @import("udp_packet.zig");
const sock = @import("../common/sock.zig");
const buf = @import("../common/buf.zig");
const net = @import("../common/net.zig");
const stream = @import("../core/stream.zig");
const applog = @import("../app/log.zig");
const conf_freedom = @import("../conf/freedom.zig");
const trace_mod = @import("../app/trace.zig");

pub const BuiltRule = conf_freedom.FinalRule.Built;
pub const RuleAction = conf_freedom.RuleAction;

// ============================ 内置默认规则 ============================

/// 内置默认规则类型（freedom.go getDefaultFinalRule，按入站名判定）
pub const DefaultRuleKind = enum {
    none,
    block_all, // vless-reverse
    block_private, // vless / vmess / trojan / hysteria / wireguard / shadowsocks*
};

pub fn defaultRuleForInbound(inbound_name: []const u8) DefaultRuleKind {
    if (std.mem.eql(u8, inbound_name, "vless-reverse")) return .block_all;
    const names = [_][]const u8{ "vless", "vmess", "trojan", "hysteria", "wireguard" };
    for (names) |n| {
        if (std.mem.eql(u8, inbound_name, n)) return .block_private;
    }
    if (std.mem.startsWith(u8, inbound_name, "shadowsocks")) return .block_private;
    return .none;
}

/// 私网 IP 清单（common/geodata/consts.go:10-29 共 18 条，逐条照抄）
const PrivateV4 = struct { prefix: [4]u8, bits: u8 };
const private_v4_rules = [_]PrivateV4{
    .{ .prefix = .{ 0, 0, 0, 0 }, .bits = 8 }, // 0.0.0.0/8
    .{ .prefix = .{ 10, 0, 0, 0 }, .bits = 8 }, // 10.0.0.0/8
    .{ .prefix = .{ 100, 64, 0, 0 }, .bits = 10 }, // 100.64.0.0/10
    .{ .prefix = .{ 127, 0, 0, 0 }, .bits = 8 }, // 127.0.0.0/8
    .{ .prefix = .{ 169, 254, 0, 0 }, .bits = 16 }, // 169.254.0.0/16
    .{ .prefix = .{ 172, 16, 0, 0 }, .bits = 12 }, // 172.16.0.0/12
    .{ .prefix = .{ 192, 0, 0, 0 }, .bits = 24 }, // 192.0.0.0/24
    .{ .prefix = .{ 192, 0, 2, 0 }, .bits = 24 }, // 192.0.2.0/24
    .{ .prefix = .{ 192, 88, 99, 0 }, .bits = 24 }, // 192.88.99.0/24
    .{ .prefix = .{ 192, 168, 0, 0 }, .bits = 16 }, // 192.168.0.0/16
    .{ .prefix = .{ 198, 18, 0, 0 }, .bits = 15 }, // 198.18.0.0/15
    .{ .prefix = .{ 198, 51, 100, 0 }, .bits = 24 }, // 198.51.100.0/24
    .{ .prefix = .{ 203, 0, 113, 0 }, .bits = 24 }, // 203.0.113.0/24
    .{ .prefix = .{ 224, 0, 0, 0 }, .bits = 3 }, // 224.0.0.0/3
};

fn v6p(a: u8, b: u8) [16]u8 {
    var out: [16]u8 = @splat(0);
    out[0] = a;
    out[1] = b;
    return out;
}

const PrivateV6 = struct { prefix: [16]u8, bits: u8 };
const private_v6_rules = [_]PrivateV6{
    .{ .prefix = @splat(0), .bits = 127 }, // ::/127（覆盖未指定地址与 ::1，非 ::1/128）
    .{ .prefix = v6p(0xfc, 0x00), .bits = 7 }, // fc00::/7
    .{ .prefix = v6p(0xfe, 0x80), .bits = 10 }, // fe80::/10
    .{ .prefix = v6p(0xff, 0x00), .bits = 8 }, // ff00::/8
};

fn v4Match(ip: [4]u8, prefix: [4]u8, bits: u8) bool {
    const full = bits / 8;
    if (!std.mem.eql(u8, ip[0..full], prefix[0..full])) return false;
    const rem = bits % 8;
    if (rem == 0) return true;
    const mask: u8 = @as(u8, 0xff) << @intCast(8 - rem);
    return (ip[full] & mask) == (prefix[full] & mask);
}

fn v6Match(ip: [16]u8, prefix: [16]u8, bits: u8) bool {
    const full = bits / 8;
    if (!std.mem.eql(u8, ip[0..full], prefix[0..full])) return false;
    const rem = bits % 8;
    if (rem == 0) return true;
    const mask: u8 = @as(u8, 0xff) << @intCast(8 - rem);
    return (ip[full] & mask) == (prefix[full] & mask);
}

/// GetPrivateIPMatcher 等价物（v4/v6 字节序列）
pub fn isPrivateIp(ip: []const u8) bool {
    switch (ip.len) {
        4 => {
            const b: [4]u8 = ip[0..4].*;
            for (private_v4_rules) |r| {
                if (v4Match(b, r.prefix, r.bits)) return true;
            }
        },
        16 => {
            const b: [16]u8 = ip[0..16].*;
            for (private_v6_rules) |r| {
                if (v6Match(b, r.prefix, r.bits)) return true;
            }
        },
        else => {},
    }
    return false;
}

// ============================ 规则求值 ============================

/// 规则求值结果（action + blockDelay 区间；默认规则 30–90s）
pub const Eval = struct {
    action: RuleAction,
    delay_min: u64,
    delay_max: u64,
};

pub const default_delay_min: u64 = 30;
pub const default_delay_max: u64 = 90;

/// Go FinalRule.Apply：network && port && ip（ip 匹配器非空时域名目标不匹配）
fn applyRule(rule: BuiltRule, network: net.Network, ip: ?[]const u8, port: u16) bool {
    const n: conf_freedom.Network = switch (network) {
        .tcp => .tcp,
        .udp => .udp,
    };
    if (!rule.matchNetwork(n)) return false;
    if (!rule.matchPort(port)) return false;
    if (rule.ip_rules.len == 0) return true;
    const bytes = ip orelse return false;
    return rule.matchIp(bytes);
}

/// Go matchFinalRule：用户规则按序首条命中；未命中再求内置默认规则
pub fn evalMatch(
    rules: []const BuiltRule,
    default_kind: DefaultRuleKind,
    network: net.Network,
    ip: ?[]const u8,
    port: u16,
) ?Eval {
    for (rules) |r| {
        if (applyRule(r, network, ip, port)) {
            return .{ .action = r.action, .delay_min = r.block_delay_min, .delay_max = r.block_delay_max };
        }
    }
    switch (default_kind) {
        .none => {},
        .block_all => return .{ .action = .block, .delay_min = default_delay_min, .delay_max = default_delay_max },
        .block_private => {
            if (ip) |b| {
                if (isPrivateIp(b)) {
                    return .{ .action = .block, .delay_min = default_delay_min, .delay_max = default_delay_max };
                }
            }
        },
    }
    return null;
}

/// D1：域名目标何时做 DNS 预检——
///   1) 任一用户规则带 ip 匹配器 → 做；
///   2) 内置默认规则可达（没有无条件用户规则遮蔽它）→ 做；
///   3) 否则跳过（本配置 [{action:"allow"}] 命中第 3 条：预检结果与 IP 无关）。
fn needDomainPrecheck(rules: []const BuiltRule, default_kind: DefaultRuleKind) bool {
    for (rules) |r| {
        if (r.ip_rules.len > 0) return true;
    }
    if (default_kind == .none) return false;
    for (rules) |r| {
        if (r.networks.len == 0 and r.ports.len == 0 and r.ip_rules.len == 0) return false;
    }
    return true;
}

/// Go blockDelay：min + Roll(span+1)，span 为 |max-min|；区间含端点
fn rollDelay(rule: Eval) u64 {
    const min = rule.delay_min;
    const max = rule.delay_max;
    const span: u64 = if (max >= min) max - min else min - max;
    const n: u64 = if (span == std.math.maxInt(u64)) span else span + 1; // span+1 溢出保护
    if (n <= 1) return min;
    var rb: [8]u8 = undefined;
    sys.randomBytes(&rb);
    const r = std.mem.readInt(u64, &rb, .little);
    return min + (r % n);
}

/// Go time.Duration 整秒形态："37s" / "1m0s" / "1m30s"（秒位不补零）
fn formatGoSeconds(out: []u8, secs: u64) []const u8 {
    if (secs < 60) {
        return std.fmt.bufPrint(out, "{d}s", .{secs}) catch "0s";
    }
    return std.fmt.bufPrint(out, "{d}m{d}s", .{ secs / 60, secs % 60 }) catch "0s";
}

// ============================ Handler ============================

pub const Handler = struct {
    logger: *applog.Logger,
    pool: *buf.Pool,
    rules: []const BuiltRule = &.{},

    pub const ProcessError = error{
        TargetNotSpecified,
        DialFailed,
        OutOfMemory,
    };

    const dial_timeout_ms: i64 = 16 * 1000;
    const dial_attempts = 5;
    const dial_backoff_base_ms: u32 = 100;

    fn logDest(self: *Handler, sev: applog.Severity, comptime fmt: []const u8, dest: net.Destination, args: anytype) void {
        var dbuf: [96]u8 = undefined;
        const dn = dest.format(&dbuf);
        var lbuf: [512]u8 = undefined;
        const msg = std.fmt.bufPrint(&lbuf, fmt, .{dbuf[0..dn]} ++ args) catch return;
        self.logger.log(sev, msg);
    }

    /// Go retry.ExponentialBackoff(5, 100)：共 5 次尝试，失败间隔 0/100/200/300/400ms
    fn dialWithRetry(self: *Handler, arena: std.mem.Allocator, dest: net.Destination) ProcessError!sock.TcpConn {
        _ = self;
        var next_delay: u32 = 0;
        var attempt: usize = 0;
        while (attempt < dial_attempts) : (attempt += 1) {
            const sa = resolveTarget(arena, dest) orelse {
                sys.sleepMs(next_delay);
                next_delay += dial_backoff_base_ms;
                continue;
            };
            if (sock.dialTcp(.{ .v4 = sa }, dial_timeout_ms)) |conn| {
                sock.setKeepalive45(conn.fd);
                return conn;
            } else |_| {
                sys.sleepMs(next_delay);
                next_delay += dial_backoff_base_ms;
            }
        }
        return ProcessError.DialFailed;
    }

    /// Go blackhole：上行全丢弃，延迟后断开；客户端提前 EOF 则提前结束
    /// （Go: buf.Copy 返回 → defer timer.Stop + Close(output)）。
    fn blackhole(self: *Handler, rule: Eval, dest: net.Destination, client: stream.Link) void {
        const delay_s = rollDelay(rule);
        var dsec_buf: [32]u8 = undefined;
        const delay_str = formatGoSeconds(&dsec_buf, delay_s);
        self.logDest(.info, "blocked target: {s}, blackholing connection for {s}", dest, .{delay_str});

        const start = sys.nowMonoMs();
        const delay_ms: i64 = @intCast(delay_s * 1000);
        var rbuf: [buf.buffer_size]u8 = undefined;
        while (true) {
            const elapsed = sys.nowMonoMs() - start;
            if (elapsed >= delay_ms) break;
            client.reader.setTimeout(delay_ms - elapsed);
            const n = client.reader.read(&rbuf) catch break; // RST 等错误 → 提前结束
            if (n == 0) break; // EOF → 提前结束
            // 丢弃（buf.Discard 语义）
        }
        self.logDest(.info, "closed blackholed connection to blocked target: {s}", dest, .{});
        client.writer.shutdownWrite();
    }

    pub fn process(
        self: *Handler,
        arena: std.mem.Allocator,
        sess: *const buf.Session,
        dest: net.Destination,
        client: stream.Link,
        /// M15 统计计数器（上游 WrapLink 语义）；null = 本连接不计数
        stat: ?*const stats_mod.Counters,
    ) ProcessError!void {
        if (!dest.isValid()) return ProcessError.TargetNotSpecified;

        const default_kind = defaultRuleForInbound(sess.inbound_protocol);

        // ---- 拨号前阻断判定 ----
        var blocked: ?net.Destination = null;
        var blocked_eval: Eval = .{ .action = .block, .delay_min = default_delay_min, .delay_max = default_delay_max };

        switch (dest.address) {
            .domain => |d| {
                if (needDomainPrecheck(self.rules, default_kind)) {
                    // D1 预检：首个 A 记录（AsIs 语义下拨号仍传域名，由系统解析）
                    if (sock.resolveV4(arena, d)) |ip| {
                        if (evalMatch(self.rules, default_kind, dest.network, &ip, dest.port)) |m| {
                            if (m.action == .block) {
                                blocked = .{ .network = dest.network, .address = .{ .ipv4 = ip }, .port = dest.port };
                                blocked_eval = m;
                            }
                        }
                    }
                    // 解析失败 → 照拨（Go 非 force 策略同样继续，由拨号再解析）
                }
            },
            .ipv4, .ipv6 => {
                const bytes: []const u8 = switch (dest.address) {
                    .ipv4 => |b| b[0..],
                    .ipv6 => |b| b[0..],
                    .domain => unreachable,
                };
                if (evalMatch(self.rules, default_kind, dest.network, bytes, dest.port)) |m| {
                    if (m.action == .block) {
                        blocked = dest;
                        blocked_eval = m;
                    }
                }
            },
        }

        // ---- 拨号 ----
        var remote: sock.TcpConn = undefined;
        if (blocked == null) {
            // M17：UDP 目标走独立分支（对照上游 freedom.go Network_UDP 分支）
            if (dest.network == .udp) return processUdp(self.logger, arena, dest, client, stat, sess.trace);
            const t_dial = trace_mod.stamp(sess.trace);
            remote = self.dialWithRetry(arena, dest) catch |e| {
                if (e == ProcessError.DialFailed) {
                    self.logDest(.warning, "failed to open connection to {s}", dest, .{});
                    if (sess.trace) |tr| {
                        // 失败也记耗时：DNS 卡住 vs 直接 refused，调优方向完全不同
                        var db: [96]u8 = undefined;
                        const dn = dest.format(&db);
                        tr.markDial(if (t_dial > 0) sys.nowMonoMs() - t_dial else 0, db[0..dn]);
                        tr.setReason(.dial_fail);
                        trace_mod.countDialFail();
                    }
                }
                return e;
            };
            if (sess.trace) |tr| {
                // 拨号成功的耗时与**实际连上的地址**（域名目标可见解析结果）
                var pb: [64]u8 = undefined;
                const pn = remote.peerAddr(&pb);
                tr.markDial(if (t_dial > 0) sys.nowMonoMs() - t_dial else 0, pb[0..pn]);
            }
            // 域名目标：按实际连接地址复检 block 规则（freedom.go:353-360）
            if (dest.address == .domain and (self.rules.len > 0 or default_kind != .none)) {
                if (remote.peerV4()) |peer| {
                    if (evalMatch(self.rules, default_kind, dest.network, &peer.addr, peer.port)) |m| {
                        if (m.action == .block) {
                            remote.close();
                            blocked = .{ .network = dest.network, .address = .{ .ipv4 = peer.addr }, .port = peer.port };
                            blocked_eval = m;
                        }
                    }
                }
            }
        }

        if (blocked) |bdest| {
            if (sess.trace) |tr| tr.setReason(.blocked);
            self.blackhole(blocked_eval, bdest, client);
            return;
        }

        // ---- 数据面：双向拷贝（task.Run(requestDone, responseDone) 的线程版） ----
        {
            var dbuf: [96]u8 = undefined;
            var lbuf: [64]u8 = undefined;
            var rbuf: [64]u8 = undefined;
            const dn = dest.format(&dbuf);
            const ln = remote.localAddr(&lbuf);
            const rn = remote.peerAddr(&rbuf);
            var mb: [384]u8 = undefined;
            if (std.fmt.bufPrint(&mb, "connection opened to {s}, local endpoint {s}, remote endpoint {s}", .{
                dbuf[0..dn], lbuf[0..ln], rbuf[0..rn],
            })) |msg| {
                self.logger.info(msg);
            } else |_| {}
        }

        const remote_ctx = arena.create(stream.TcpStreamCtx) catch return ProcessError.OutOfMemory;
        remote_ctx.* = .{ .conn = remote };
        const remote_stream = remote_ctx.stream();

        const shared = arena.create(CopyShared) catch return ProcessError.OutOfMemory;
        shared.* = .{};

        // M15：4 个计数器槽按方向分配（上游 WrapLink：Reader→uplink、Writer→downlink）
        var up_list: [2]*stats_mod.Counter = undefined;
        var down_list: [2]*stats_mod.Counter = undefined;
        var up_n: usize = 0;
        var down_n: usize = 0;
        if (stat) |c| {
            if (c.inbound_up) |x| {
                up_list[up_n] = x;
                up_n += 1;
            }
            if (c.user_up) |x| {
                up_list[up_n] = x;
                up_n += 1;
            }
            if (c.inbound_down) |x| {
                down_list[down_n] = x;
                down_n += 1;
            }
            if (c.user_down) |x| {
                down_list[down_n] = x;
                down_n += 1;
            }
        }

        const up = CopyJob{ .handler = self, .shared = shared, .dir = .up, .src = client.reader, .dst = remote_stream, .remote = remote, .up_stats = up_list[0..up_n], .down_stats = down_list[0..down_n], .trace = sess.trace };
        const down = CopyJob{ .handler = self, .shared = shared, .dir = .down, .src = remote_stream, .dst = client.writer, .remote = remote, .up_stats = up_list[0..up_n], .down_stats = down_list[0..down_n], .trace = sess.trace };

        // M24 线程账：只 spawn **下行**线程，上行拷贝在**调用线程**里跑。
        // 原实现每连接 3 线程（协议线程 + 2 拷贝），现在 2 线程（协议线程兼任上行拷贝）。
        // 安全性：调用线程（connEntry / mux sessionMain）本来就是"阻塞等 dispatch 返回"，
        // 让它顺带跑上行不改变任何语义；up 结束时 up_done=true 会让 down 在 1s 内收尾。
        // ⚠️ 调用线程栈必须 ≥ crypto_thread_stack（copyMain 内含 32KB 缓冲 + 协议体编解码）。
        const down_thread = std.Thread.spawn(.{ .stack_size = sys.crypto_thread_stack }, copyMain, .{down}) catch {
            shared.failed.store(true, .release);
            remote.close();
            return ProcessError.OutOfMemory;
        };
        copyMain(up);
        down_thread.join();
        remote.close();
    }
};

// ============================ 拷贝线程 ============================

const Direction = enum { up, down };

/// 拷贝对共享状态：对向结束后本向进入 1s 收尾阈值（UplinkOnly/DownlinkOnly）
const CopyShared = struct {
    up_done: std.atomic.Value(bool) = .init(false),
    down_done: std.atomic.Value(bool) = .init(false),
    failed: std.atomic.Value(bool) = .init(false),
};

const CopyJob = struct {
    handler: *Handler,
    shared: *CopyShared,
    dir: Direction,
    src: stream.Stream, // up: 客户端；down: 远端
    dst: stream.Stream, // up: 远端；down: 客户端
    remote: sock.TcpConn, // 出错唤醒用（Stream 无双向 shutdown）
    /// M15：本方向要累加的计数器（up: 读客户端数据 → uplink；down: 写给客户端 → downlink）
    up_stats: []const *stats_mod.Counter = &.{},
    down_stats: []const *stats_mod.Counter = &.{},
    /// 连接打点（null / off = 热路径零开销）
    trace: ?*trace_mod.Trace = null,
};

/// 拨号目标解析（从 Handler 提为模块级：processUdp 亦需使用）
fn resolveTarget(arena: std.mem.Allocator, dest: net.Destination) ?sys.SockaddrIn {
    switch (dest.address) {
        .ipv4 => |b| return sys.SockaddrIn.init(b, dest.port),
        .domain => |d| {
            const ip = sock.resolveV4(arena, d) orelse return null;
            return sys.SockaddrIn.init(ip, dest.port);
        },
        .ipv6 => return null, // Phase 1 拨号面 v4-only（sock 层 AF.INET）
    }
}

/// M17 UDP 会话共享状态（无 shutdown 语义：退出靠 idle 阈值 + 对向 done 传播）
const UdpShared = struct {
    failed: std.atomic.Value(bool) = .init(false),
    up_done: std.atomic.Value(bool) = .init(false),
    down_done: std.atomic.Value(bool) = .init(false),
};

const UdpCopy = struct {
    shared: *UdpShared,
    conn: sock.UdpConn,
    client: stream.Link,
    dir: Direction,
    up_stats: []const *stats_mod.Counter = &.{},
    down_stats: []const *stats_mod.Counter = &.{},
    /// 连接打点（null / off = 零开销）
    trace: ?*trace_mod.Trace = null,
};

fn udpCopyMain(job: *UdpCopy) void {
    var last_activity = sys.nowMonoMs();
    var b: [udp_pkt.MAX_PACKET]u8 = undefined;
    while (true) {
        // 对向已结束 -> 收尾阈值 1s（同 TCP 的 UplinkOnly/DownlinkOnly）
        const threshold: i64 = switch (job.dir) {
            .up => if (job.shared.down_done.load(.acquire)) buf.Policy.uplink_only_ms else buf.Policy.connection_idle_ms,
            .down => if (job.shared.up_done.load(.acquire)) buf.Policy.downlink_only_ms else buf.Policy.connection_idle_ms,
        };
        switch (job.dir) {
            .up => {
                // 读 length-prefixed 包 -> send
                const t_r = trace_mod.stamp(job.trace);
                const n = udp_pkt.readPacket(job.client.reader, &b) catch {
                    job.shared.failed.store(true, .release);
                    if (job.trace) |tr| tr.setReason(.reset);
                    break;
                };
                const read_ms: u32 = if (t_r > 0) @intCast(@max(0, sys.nowMonoMs() - t_r)) else 0;
                last_activity = sys.nowMonoMs();
                for (job.up_stats) |c| c.add(n);
                const t_w = trace_mod.stamp(job.trace);
                job.conn.send(b[0..n]) catch {
                    job.shared.failed.store(true, .release);
                    if (job.trace) |tr| tr.setReason(.reset);
                    break;
                };
                if (job.trace) |tr| {
                    const wr_ms: u32 = if (t_w > 0) @intCast(@max(0, sys.nowMonoMs() - t_w)) else 0;
                    tr.onData(true, n, read_ms, wr_ms);
                }
            },
            .down => {
                // recv（1s 切片）-> 写 length-prefixed 包
                job.conn.setTimeout(1000);
                const t_r = trace_mod.stamp(job.trace);
                const n = job.conn.recv(&b) catch |e| {
                    if (e == error.TimedOut) {
                        if (sys.nowMonoMs() - last_activity >= threshold) {
                            job.shared.failed.store(true, .release);
                            if (job.trace) |tr| tr.setReason(.idle_timeout);
                            break;
                        }
                        continue;
                    }
                    job.shared.failed.store(true, .release);
                    if (job.trace) |tr| tr.setReason(.reset);
                    break;
                };
                const read_ms: u32 = if (t_r > 0) @intCast(@max(0, sys.nowMonoMs() - t_r)) else 0;
                last_activity = sys.nowMonoMs();
                for (job.down_stats) |c| c.add(n);
                const t_w = trace_mod.stamp(job.trace);
                udp_pkt.writePacket(job.client.writer, b[0..n]) catch {
                    job.shared.failed.store(true, .release);
                    if (job.trace) |tr| tr.setReason(.reset);
                    break;
                };
                if (job.trace) |tr| {
                    const wr_ms: u32 = if (t_w > 0) @intCast(@max(0, sys.nowMonoMs() - t_w)) else 0;
                    tr.onData(false, n, read_ms, wr_ms);
                }
            },
        }
    }
    switch (job.dir) {
        .up => job.shared.up_done.store(true, .release),
        .down => {
            job.shared.down_done.store(true, .release);
            // M20 修复：与 TCP 的 copyMain 一致——下行结束必须半关闭"写向客户端"的流
            //（Go 对应 responseDone 的 defer task.Close(output)）。
            //
            // 漏了这一步的后果（XUDP over mux 特有）：mux 的 DownWriter 靠下行管道 EOF
            // 才知道该发 End 帧收尾；下行写侧永不关闭 → DownWriter 在 Pipe.read 里
            // 1ms 轮询**永不退出** → 该线程永不 leave() → serve 的 waitInflight() 在
            // mux 连接关闭时**永久阻塞** → connEntry 线程 + sess_arena 全部泄漏，
            // 256 并发上限被僵尸连接吃满后表现为"新连接全被拒"。
            job.client.writer.shutdownWrite();
        },
    }
}

/// M17：UDP 会话双向拷贝（对照上游 freedom.go Network_UDP 分支：PacketWriter/PacketReader）。
/// 模块级函数（不依赖 Handler 状态；日志经 logger）。
fn processUdp(
    logger: *applog.Logger,
    arena: std.mem.Allocator,
    dest: net.Destination,
    client: stream.Link,
    stat: ?*const stats_mod.Counters,
    trace: ?*trace_mod.Trace,
) Handler.ProcessError!void {
    // ExponentialBackoff(5, 100)：5 次尝试，间隔 0/100/200/300/400ms（同 dialWithRetry）
    const t_dial = trace_mod.stamp(trace);
    var remote: ?sock.UdpConn = null;
    var next_delay: u32 = 0;
    var attempt: usize = 0;
    while (attempt < 5) : (attempt += 1) {
        const sa = resolveTarget(arena, dest) orelse {
            sys.sleepMs(next_delay);
            next_delay += 100;
            continue;
        };
        if (sock.dialUdp(.{ .v4 = sa })) |c| {
            remote = c;
            break;
        } else |_| {
            sys.sleepMs(next_delay);
            next_delay += 100;
        }
    }
    const rconn = remote orelse {
        var db: [96]u8 = undefined;
        const dn = dest.format(&db);
        var lb: [160]u8 = undefined;
        if (std.fmt.bufPrint(&lb, "failed to open connection to {s}", .{db[0..dn]})) |m| {
            logger.warning(m);
        } else |_| {}
        if (trace) |tr| {
            tr.markDial(if (t_dial > 0) sys.nowMonoMs() - t_dial else 0, db[0..dn]);
            tr.setReason(.dial_fail);
            trace_mod.countDialFail();
        }
        return Handler.ProcessError.DialFailed;
    };
    defer rconn.close();
    if (trace) |tr| tr.markDial(if (t_dial > 0) sys.nowMonoMs() - t_dial else 0, "udp");

    const shared = arena.create(UdpShared) catch return Handler.ProcessError.OutOfMemory;
    shared.* = .{};

    // M15 计数槽（同 TCP 分配逻辑）
    var up_list: [2]*stats_mod.Counter = undefined;
    var down_list: [2]*stats_mod.Counter = undefined;
    var up_n: usize = 0;
    var down_n: usize = 0;
    if (stat) |c| {
        if (c.inbound_up) |x| {
            up_list[up_n] = x;
            up_n += 1;
        }
        if (c.user_up) |x| {
            up_list[up_n] = x;
            up_n += 1;
        }
        if (c.inbound_down) |x| {
            down_list[down_n] = x;
            down_n += 1;
        }
        if (c.user_down) |x| {
            down_list[down_n] = x;
            down_n += 1;
        }
    }

    var up = UdpCopy{ .shared = shared, .conn = rconn, .client = client, .dir = .up, .up_stats = up_list[0..up_n], .down_stats = down_list[0..down_n], .trace = trace };
    var down = UdpCopy{ .shared = shared, .conn = rconn, .client = client, .dir = .down, .up_stats = up_list[0..up_n], .down_stats = down_list[0..down_n], .trace = trace };
    // M26 线程账（UDP 同 TCP 手法）：只 spawn 下行，上行在调用线程跑。
    // XUDP 会话线程 4 → 3（DownWriter + 出站/上行 + 下行拷贝）。
    // `up`/`down` 都在本栈帧，defer join 保证 down 存活到 join 完成。
    const t2 = std.Thread.spawn(.{ .stack_size = sys.min_thread_stack }, udpCopyMain, .{&down}) catch {
        shared.failed.store(true, .release);
        return Handler.ProcessError.OutOfMemory;
    };
    defer t2.join();
    udpCopyMain(&up);
}

fn currentThreshold(shared: *const CopyShared, dir: Direction) i64 {
    return switch (dir) {
        .up => if (shared.down_done.load(.acquire)) buf.Policy.uplink_only_ms else buf.Policy.connection_idle_ms,
        .down => if (shared.up_done.load(.acquire)) buf.Policy.downlink_only_ms else buf.Policy.connection_idle_ms,
    };
}

/// M23：拷贝缓冲大小。strace 实测 Go 服务端一次 readv 约 52KB（1MiB 只 20 次读），
/// 我们原用 8KB pool buffer → 104 次 recvfrom + 104 轮循环（每轮还带 setsockopt）。
/// 32KB 后循环/唤醒/syscall 降 4 倍；用栈缓冲而非 pool，省掉 pool 的互斥锁与 malloc。
const copy_buf_size: usize = 32 * 1024;

fn copyMain(job: CopyJob) void {
    const shared = job.shared;
    var last_activity = sys.nowMonoMs();
    // ⚠️ 超时**必须每轮重设，不能缓存**（M23 踩坑）：
    // WS 的 reader/writer 是同一个 Session，底层是**同一个 socket fd**；
    // up 线程给 src 设 1s（切片轮询）、down 线程给 dst 设 threshold（300s）会互相覆盖。
    // 原实现每轮都设，天然把竞态影响压到最小；一旦改成"只在变化时设"，
    // 就会出现读超时被对方改成 300s → 测试/会话永久阻塞（全量测试 117/166、162/166 卡死）。
    // 收益改从**缓冲大小**拿：32KB 后循环数 128→32，setsockopt 与 recvfrom 同步降 4 倍。
    var b: [copy_buf_size]u8 = undefined;
    while (true) {
        const threshold = currentThreshold(shared, job.dir);
        // 读按 1s 切片轮询，让「对向 EOF → 1s 收尾」的阈值动态生效（必须每轮设，见上）
        job.src.setTimeout(1000);
        // 打点：t_r/t_w 只在开启时取时钟（关闭时 stamp 直接返回 0，不产生 syscall）
        const t_r = trace_mod.stamp(job.trace);
        const n: usize = job.src.read(b[0..]) catch |e| {
            if (e == error.Timeout) {
                if (sys.nowMonoMs() - last_activity >= threshold) {
                    shared.failed.store(true, .release);
                    if (job.trace) |tr| tr.setReason(.idle_timeout);
                    break;
                }
                continue;
            }
            shared.failed.store(true, .release);
            if (job.trace) |tr| tr.setReason(.reset);
            break;
        };
        if (n == 0) { // EOF
            if (job.trace) |tr| tr.setReason(.eof);
            break;
        }
        const read_ms: u32 = if (t_r > 0) @intCast(@max(0, sys.nowMonoMs() - t_r)) else 0;
        last_activity = sys.nowMonoMs();
        // M15 计数：up 方向在读成功后计（客户端→服务端）；down 方向在写成功后计
        //（服务端→客户端，严格对应上游 SizeStatWriter 的写时语义）
        if (job.dir == .up) {
            for (job.up_stats) |c| c.add(n);
        }
        job.dst.setTimeout(threshold);
        const t_w = trace_mod.stamp(job.trace);
        job.dst.writeAll(b[0..n]) catch {
            shared.failed.store(true, .release);
            if (job.trace) |tr| tr.setReason(.reset);
            break;
        };
        if (job.trace) |tr| {
            const wr_ms: u32 = if (t_w > 0) @intCast(@max(0, sys.nowMonoMs() - t_w)) else 0;
            tr.onData(job.dir == .up, n, read_ms, wr_ms);
        }
        if (job.dir == .down) {
            for (job.down_stats) |c| c.add(n);
        }
    }
    // 收尾（Go 对应：requestDone/responseDone 的 defer timer.SetTimeout + task.Close(output)）
    switch (job.dir) {
        .up => {
            shared.up_done.store(true, .release);
            if (shared.failed.load(.acquire)) job.remote.shutdownAll(); // 唤醒阻塞在远端 read 的下行线程
        },
        .down => {
            shared.down_done.store(true, .release);
            job.dst.shutdownWrite(); // 客户端方向半关闭（EOF 传播）
        },
    }
}

// ============================ 测试 ============================

const testecho = @import("../testing/echo.zig");

test "private ip matcher (geodata consts 18 条抽查)" {
    try std.testing.expect(isPrivateIp(&.{ 10, 1, 2, 3 }));
    try std.testing.expect(isPrivateIp(&.{ 100, 64, 0, 1 })); // 100.64/10 下界
    try std.testing.expect(isPrivateIp(&.{ 100, 127, 255, 255 })); // 上界
    try std.testing.expect(!isPrivateIp(&.{ 100, 128, 0, 1 }));
    try std.testing.expect(!isPrivateIp(&.{ 172, 15, 0, 1 }));
    try std.testing.expect(isPrivateIp(&.{ 172, 16, 0, 1 }));
    try std.testing.expect(isPrivateIp(&.{ 172, 31, 255, 255 }));
    try std.testing.expect(!isPrivateIp(&.{ 172, 32, 0, 1 }));
    try std.testing.expect(isPrivateIp(&.{ 192, 168, 1, 1 }));
    try std.testing.expect(isPrivateIp(&.{ 198, 19, 0, 1 })); // 198.18/15
    try std.testing.expect(!isPrivateIp(&.{ 198, 20, 0, 1 }));
    try std.testing.expect(isPrivateIp(&.{ 224, 0, 0, 1 })); // 224/3
    try std.testing.expect(isPrivateIp(&.{ 250, 1, 2, 3 })); // 224/3 覆盖到 255
    try std.testing.expect(!isPrivateIp(&.{ 223, 255, 255, 255 }));
    try std.testing.expect(isPrivateIp(&.{ 127, 0, 0, 1 }));
    try std.testing.expect(isPrivateIp(&.{ 0, 0, 0, 0 }));
    // v6
    try std.testing.expect(isPrivateIp(&@as([16]u8, @splat(0)))); // ::
    try std.testing.expect(isPrivateIp(&([_]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 }))); // ::1
    try std.testing.expect(!isPrivateIp(&([_]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2 }))); // ::2 → ::/127 之外
    try std.testing.expect(isPrivateIp(&v6p(0xfc, 0))); // fc00::/7
    try std.testing.expect(!isPrivateIp(&v6p(0xfb, 0)));
    try std.testing.expect(isPrivateIp(&v6p(0xfe, 0x80))); // fe80::/10
    try std.testing.expect(isPrivateIp(&v6p(0xff, 0x02))); // ff00::/8
    try std.testing.expect(!isPrivateIp(&.{ 8, 8, 8, 8 }));
}

test "default rule by inbound name (freedom.go getDefaultFinalRule)" {
    try std.testing.expectEqual(DefaultRuleKind.block_private, defaultRuleForInbound("vless"));
    try std.testing.expectEqual(DefaultRuleKind.block_private, defaultRuleForInbound("vmess"));
    try std.testing.expectEqual(DefaultRuleKind.block_private, defaultRuleForInbound("trojan"));
    try std.testing.expectEqual(DefaultRuleKind.block_private, defaultRuleForInbound("wireguard"));
    try std.testing.expectEqual(DefaultRuleKind.block_private, defaultRuleForInbound("shadowsocks-2022"));
    try std.testing.expectEqual(DefaultRuleKind.block_all, defaultRuleForInbound("vless-reverse"));
    try std.testing.expectEqual(DefaultRuleKind.none, defaultRuleForInbound("http"));
    try std.testing.expectEqual(DefaultRuleKind.none, defaultRuleForInbound(""));
}

test "eval: first-match-wins; allow 压制内置私网屏蔽（本配置核心语义）" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const allow_rule = (conf_freedom.FinalRule{ .action = "allow" }).build(arena) catch unreachable;
    const private = [_]u8{ 192, 168, 1, 1 };
    const public = [_]u8{ 8, 8, 8, 8 };

    // 用户 allow 规则命中 → 默认私网屏蔽永不生效
    const e1 = evalMatch(&.{allow_rule}, .block_private, .tcp, &private, 443).?;
    try std.testing.expectEqual(RuleAction.allow, e1.action);

    // 无用户规则 + vless 入站 → 私网被默认规则屏蔽
    const e2 = evalMatch(&.{}, .block_private, .tcp, &private, 443).?;
    try std.testing.expectEqual(RuleAction.block, e2.action);
    try std.testing.expectEqual(default_delay_min, e2.delay_min);
    try std.testing.expectEqual(default_delay_max, e2.delay_max);

    // 无用户规则 + 公网目标 → 无规则命中（放行拨号）
    try std.testing.expectEqual(@as(?Eval, null), evalMatch(&.{}, .block_private, .tcp, &public, 443));

    // vless-reverse → block_all
    const e3 = evalMatch(&.{}, .block_all, .tcp, &public, 443).?;
    try std.testing.expectEqual(RuleAction.block, e3.action);

    // none 入站 + 无用户规则 → 恒放行
    try std.testing.expectEqual(@as(?Eval, null), evalMatch(&.{}, .none, .tcp, &private, 443));

    // 带 ip 匹配器的 block 规则：域名目标不匹配（Go matchIP 语义）
    const block_rule = (conf_freedom.FinalRule{ .action = "block", .ip = "10.0.0.0/8" }).build(arena) catch unreachable;
    try std.testing.expectEqual(@as(?Eval, null), evalMatch(&.{block_rule}, .none, .tcp, null, 443));
    const e4 = evalMatch(&.{block_rule}, .none, .tcp, &.{ 10, 2, 3, 4 }, 443).?;
    try std.testing.expectEqual(RuleAction.block, e4.action);
}

test "needDomainPrecheck (D1)" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const allow_rule = (conf_freedom.FinalRule{ .action = "allow" }).build(arena) catch unreachable;
    const ip_rule = (conf_freedom.FinalRule{ .action = "block", .ip = "10.0.0.0/8" }).build(arena) catch unreachable;

    // 本配置形态：[allow] + vless（默认规则存在但被无条件规则遮蔽）→ 跳过
    try std.testing.expect(!needDomainPrecheck(&.{allow_rule}, .block_private));
    // 无用户规则 + vless → 默认私网规则可达 → 预检
    try std.testing.expect(needDomainPrecheck(&.{}, .block_private));
    // 用户规则带 ip 匹配器 → 预检
    try std.testing.expect(needDomainPrecheck(&.{ip_rule}, .none));
    // [allow] + none 入站 → 跳过
    try std.testing.expect(!needDomainPrecheck(&.{allow_rule}, .none));
    // 无规则 + none 入站 → 跳过
    try std.testing.expect(!needDomainPrecheck(&.{}, .none));
}

test "rollDelay 区间与端点" {
    var e = Eval{ .action = .block, .delay_min = 30, .delay_max = 90 };
    var i: usize = 0;
    while (i < 500) : (i += 1) {
        const d = rollDelay(e);
        try std.testing.expect(d >= 30 and d <= 90);
    }
    e = .{ .action = .block, .delay_min = 0, .delay_max = 0 };
    try std.testing.expectEqual(@as(u64, 0), rollDelay(e));
    e = .{ .action = .block, .delay_min = 5, .delay_max = 5 };
    try std.testing.expectEqual(@as(u64, 5), rollDelay(e));
}

test "formatGoSeconds" {
    var b: [32]u8 = undefined;
    try std.testing.expectEqualStrings("0s", formatGoSeconds(&b, 0));
    try std.testing.expectEqualStrings("37s", formatGoSeconds(&b, 37));
    try std.testing.expectEqualStrings("1m0s", formatGoSeconds(&b, 60));
    try std.testing.expectEqualStrings("1m30s", formatGoSeconds(&b, 90));
    try std.testing.expectEqualStrings("2m5s", formatGoSeconds(&b, 125));
}

// ---- 端到端（本地 echo 服务器 + socketpair 伪客户端） ----

const ProcArgs = struct {
    h: *Handler,
    arena: std.mem.Allocator,
    sess: *const buf.Session,
    dest: net.Destination,
    client: stream.Link,
    err: ?Handler.ProcessError = null,
};

fn procMain(a: *ProcArgs) void {
    if (a.h.process(a.arena, a.sess, a.dest, a.client, null)) |_| {
        a.err = null;
    } else |e| {
        a.err = e;
    }
}

fn runEchoRoundtrip(h: *Handler, arena: std.mem.Allocator, sess: *const buf.Session, dest: net.Destination) !void {
    var pair = try testecho.socketpairClient(arena);
    defer {
        pair.test_side.close();
        pair.deinit();
    }

    var args = ProcArgs{ .h = h, .arena = arena, .sess = sess, .dest = dest, .client = pair.link() };
    // M24：调用线程现在兼任上行拷贝（copyMain 含 32KB 缓冲），栈必须用 crypto 档
    const th = try std.Thread.spawn(.{ .stack_size = sys.crypto_thread_stack }, procMain, .{&args});

    try pair.test_side.writeAll("hello freedom");
    var rb: [64]u8 = undefined;
    pair.test_side.setTimeout(5000);
    const n = try pair.test_side.read(&rb);
    try std.testing.expectEqualStrings("hello freedom", rb[0..n]);

    // 客户端半关 → 上行 EOF → 对向 1s 收尾 → 客户端读到 EOF
    pair.test_side.shutdownWrite();
    const n2 = pair.test_side.read(&rb) catch 0;
    try std.testing.expectEqual(@as(usize, 0), n2);

    th.join();
    try std.testing.expect(args.err == null);
}

test "freedom: allow 压制内置私网屏蔽 → 127/8 目标真实拨号 echo（M3 验收锚点）" {
    // 127.0.0.1 在私网清单（127.0.0.0/8）内：
    //   - 无用户规则 + vless → 默认私网屏蔽应命中（evalMatch 测试已锚定）；
    //   - [{action:"allow"}] 命中首位 → 屏蔽被压制 → 真实拨号 + echo 往返。
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var pool = buf.Pool.init(std.testing.allocator);
    defer pool.deinit();
    var lg = applog.Logger{ .enabled = false };

    const echo = try testecho.EchoServer.start();
    defer echo.stop();

    var sess = buf.Session{};
    sess.inbound_protocol = "vless";
    sess.setSource("127.0.0.1:40001");

    const allow = (conf_freedom.FinalRule{ .action = "allow" }).build(arena) catch unreachable;
    var h = Handler{ .logger = &lg, .pool = &pool, .rules = &.{allow} };
    const dest = net.Destination{ .network = .tcp, .address = .{ .ipv4 = .{ 127, 0, 0, 1 } }, .port = echo.port() };
    try runEchoRoundtrip(&h, arena, &sess, dest);
    try std.testing.expect(echo.served.load(.monotonic) >= 1); // 真实拨号发生
}

test "freedom: block 规则 → 黑洞吞上行、零拨号、EOF 收尾（M3 验收锚点）" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var pool = buf.Pool.init(std.testing.allocator);
    defer pool.deinit();
    var lg = applog.Logger{ .enabled = false };

    const echo = try testecho.EchoServer.start();
    defer echo.stop();

    var sess = buf.Session{};
    sess.inbound_protocol = "vless";
    sess.setSource("127.0.0.1:40002");

    // block 规则 + blockDelay 0–0s（测试加速；生产默认 30–90s）
    const block0 = (conf_freedom.FinalRule{ .action = "block", .blockDelayFrom = 0, .blockDelayTo = 0 }).build(arena) catch unreachable;
    var h = Handler{ .logger = &lg, .pool = &pool, .rules = &.{block0} };
    const dest = net.Destination{ .network = .tcp, .address = .{ .ipv4 = .{ 127, 0, 0, 1 } }, .port = echo.port() };

    var pair = try testecho.socketpairClient(arena);
    defer {
        pair.test_side.close();
        pair.deinit();
    }
    var args = ProcArgs{ .h = &h, .arena = arena, .sess = &sess, .dest = dest, .client = pair.link() };
    // M24：调用线程现在兼任上行拷贝（copyMain 含 32KB 缓冲），栈必须用 crypto 档
    const th = try std.Thread.spawn(.{ .stack_size = sys.crypto_thread_stack }, procMain, .{&args});

    try pair.test_side.writeAll("should be swallowed");
    var rb: [64]u8 = undefined;
    pair.test_side.setTimeout(5000);
    // 黑洞 delay=0 → 立即 EOF（回显数据不可能出现）
    const n = pair.test_side.read(&rb) catch 0;
    try std.testing.expectEqual(@as(usize, 0), n);
    th.join();
    try std.testing.expect(args.err == null);
    try std.testing.expectEqual(@as(u32, 0), echo.served.load(.monotonic)); // 零拨号
}

test "freedom: 域名目标（D1 跳过预检）→ AsIs 拨号 echo" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var pool = buf.Pool.init(std.testing.allocator);
    defer pool.deinit();
    var lg = applog.Logger{ .enabled = false };

    const echo = try testecho.EchoServer.start();
    defer echo.stop();

    var sess = buf.Session{};
    sess.inbound_protocol = "vless";
    sess.setSource("127.0.0.1:40003");

    const allow = (conf_freedom.FinalRule{ .action = "allow" }).build(arena) catch unreachable;
    var h = Handler{ .logger = &lg, .pool = &pool, .rules = &.{allow} };
    const dest = net.Destination{ .network = .tcp, .address = .{ .domain = "localhost" }, .port = echo.port() };
    try runEchoRoundtrip(&h, arena, &sess, dest);
}

test "freedom: invalid destination 报 TargetNotSpecified" {
    var lg = applog.Logger{ .enabled = false };
    var pool = buf.Pool.init(std.testing.allocator);
    defer pool.deinit();
    var h = Handler{ .logger = &lg, .pool = &pool };
    var sess = buf.Session{};
    sess.inbound_protocol = "vless";
    var pair = testecho.socketpairClient(std.testing.allocator) catch return;
    defer {
        pair.test_side.close();
        pair.deinit();
    }
    try std.testing.expectError(
        Handler.ProcessError.TargetNotSpecified,
        h.process(std.testing.allocator, &sess, .{ .network = .tcp, .address = .{ .ipv4 = .{ 1, 2, 3, 4 } }, .port = 0 }, pair.link(), null),
    );
    try std.testing.expectError(
        Handler.ProcessError.TargetNotSpecified,
        h.process(std.testing.allocator, &sess, .{ .network = .tcp, .address = .{ .domain = "" }, .port = 443 }, pair.link(), null),
    );
}
