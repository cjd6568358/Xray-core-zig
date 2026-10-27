//! 连接生命周期打点（perf trace）—— 一条连接一行，覆盖
//! `accept → 传输面握手 → 协议头 → 出站拨号 → 数据面 → 关闭` 全流程。
//!
//! 与既有日志的分工：既有 `connection closed: …` / `mux session …` 行是**人读**的
//! 粗粒度事件（tools/commute_report.py 等脚本在解析，**格式不能动**）；本模块是
//! **机读**的性能打点，字段顺序固定、只含时点与计数，用于定向微调。
//!
//! 粒度由 `log.trace` 控制（off / summary / full）：
//!   * off     —— 只剩一次 bool 判断，热路径零额外 syscall
//!   * summary —— 每连接一行汇总（默认）
//!   * full    —— 另加各阶段 debug 行（逐阶段时间线，排障时才开）
//!
//! 汇总行格式（字段顺序固定，未取到的阶段整段省略）：
//!   trace conn=7 reason=eof dur_ms=18432 from=192.168.1.23:51234 tag=inbound-19001
//!         tr=ws proto=vless user=pb8lpgli dest=www.google.com:443 ws_ms=2
//!         hdr_wait_ms=38 hdr_parse_ms=0 dial_ms=12 ttfub_ms=41 ttfb_ms=63
//!         up=1048576 down=8388608 up_chunks=32 down_chunks=256 up_wait_ms=812
//!         down_wait_ms=1204 up_wr_ms=0 down_wr_ms=0 idle_ms=1200 mux=0
//!
//! 各指标怎么读（= 后期微调的判据）：
//!   ws_ms        accept → WS 升级完成（含客户端首个 HTTP 包到达）：大 = 链路 RTT 差
//!   hdr_wait_ms  WS 就绪 → 协议头首字节：大 = 客户端慢 / 弱网首包重传
//!   hdr_parse_ms 首字节 → 头解析完：大 = 服务端 CPU（正常应 < 2ms）
//!   dial_ms      出站拨号（含 DNS 解析）：大 = 出口网络 / DNS
//!   ttfub_ms     accept → 首个上行载荷：大 = 客户端建链后迟迟不发数据
//!   ttfb_ms      accept → 首个下行字节：端到端建链总延迟（用户感知的主指标）
//!   down_wait_ms 单次等目标数据最长：大 = 目标站慢
//!   down_wr_ms   单次写客户端最长（背压）：大 = 客户端消费慢 / 上行拥塞
//!   up_chunks    / down_chunks 读写次数：大 = 分片过碎（缓冲/MTU 可调）
//!   idle_ms      关闭前静默时长：≈ dur 说明是空闲超时收尾（非异常）
//!
//! 线程安全：一条连接的上行拷贝在协议线程、下行拷贝在独立线程，mux 子会话又会
//! 把字节量回灌父连接，故 `up/down_bytes`、`last_act`、`mux_sessions`、`reason`
//! 用原子量；其余字段单写者，join 之后才被 `finish` 读，无需原子。

const std = @import("std");
const sys = @import("../common/sys.zig");
const applog = @import("log.zig");

/// 传输面（与 conf 的 protocol_name 对齐：tcp / websocket / mkcp）
pub const Transport = enum(u8) {
    tcp,
    websocket,
    mkcp,

    pub fn tag(self: Transport) []const u8 {
        return switch (self) {
            .tcp => "tcp",
            .websocket => "ws",
            .mkcp => "kcp",
        };
    }
};

/// 关闭原因（打点里最有价值的判定字段：区分"正常空闲收尾"与"异常断链"）
pub const Reason = enum(u8) {
    unknown = 0,
    eof, // 对端正常关闭（FIN/EOF）
    reset, // RST / 读写报错
    idle_timeout, // 空闲阈值收尾（300s / 对向结束后 1s）
    shutdown, // 进程退出收尾
    overload, // 并发上限拒绝
    ws_fail, // WS 升级失败（半包头 / 解析失败 / 非 WS 请求）
    handshake_fail, // 协议握手读失败（客户端放弃 / 弱网）
    rejected, // 鉴权或协议校验失败
    unsupported, // 不支持的 command / flow
    dial_fail, // 出站拨号失败
    fallback, // 转交 fallbacks
    blocked, // 命中 block 规则 → 黑洞
    mux_end, // mux 主循环结束（整条 TCP 的 mux 通道关闭）
};

/// 慢路径告警阈值（ms）——超阈值单独打一条 [Warning]，不依赖 full 粒度，
/// 因为"慢"才是后期微调的入口，不该被日志级别淹没。
pub const slow_ws_ms: i64 = 1000;
pub const slow_hdr_wait_ms: i64 = 3000;
pub const slow_dial_ms: i64 = 2000;
pub const slow_ttfb_ms: i64 = 3000;
pub const slow_write_ms: i64 = 5000;

/// 汇总行缓冲建议大小（一行最多 ~500B；不足时按字段顺序截尾）
pub const summary_max: usize = 640;

var next_id = std.atomic.Value(u64).init(0);

fn allocId() u64 {
    return next_id.fetchAdd(1, .monotonic) + 1;
}

/// 定长拼接器：bufPrint 失败即停（保持已写入的前缀，字段顺序即重要性顺序）
const Out = struct {
    buf: []u8,
    len: usize = 0,

    fn print(self: *Out, comptime fmt: []const u8, args: anytype) void {
        if (self.len >= self.buf.len) return;
        const s = std.fmt.bufPrint(self.buf[self.len..], fmt, args) catch return;
        self.len += s.len;
    }

    fn text(self: *const Out) []const u8 {
        return self.buf[0..self.len];
    }
};

fn copyInto(dst: []u8, dst_len: *usize, s: []const u8) void {
    const n = @min(s.len, dst.len);
    @memcpy(dst[0..n], s[0..n]);
    dst_len.* = n;
}

pub const Trace = struct {
    logger: ?*applog.Logger = null,
    enabled: bool = false,
    full: bool = false,

    id: u64 = 0,
    /// mux 子会话：所属连接 id（父连接汇总里 mux=N 对应它）
    parent: ?*Trace = null,
    sid: u16 = 0,
    is_session: bool = false,

    t0: i64 = 0,
    transport: Transport = .tcp,
    protocol: []const u8 = "",

    source: [48]u8 = undefined,
    source_len: usize = 0,
    tag: [32]u8 = undefined,
    tag_len: usize = 0,
    user: [48]u8 = undefined,
    user_len: usize = 0,
    dest: [96]u8 = undefined,
    dest_len: usize = 0,

    // 阶段时点（相对 t0 的 ms；-1 = 未到达该阶段）
    ws_ms: i64 = -1,
    hdr_wait_ms: i64 = -1,
    hdr_parse_ms: i64 = -1,
    dial_ms: i64 = -1,
    up_first_ms: i64 = -1,
    down_first_ms: i64 = -1,

    // 跨线程字段
    up_bytes: std.atomic.Value(u64) = .init(0),
    down_bytes: std.atomic.Value(u64) = .init(0),
    up_chunks: std.atomic.Value(u32) = .init(0),
    down_chunks: std.atomic.Value(u32) = .init(0),
    last_act: std.atomic.Value(i64) = .init(0),
    mux_sessions: std.atomic.Value(u32) = .init(0),
    reason: std.atomic.Value(u8) = .init(@intFromEnum(Reason.unknown)),
    finished: std.atomic.Value(bool) = .init(false),

    // 单写者字段（up 线程 / down 线程各写自己那一份，join 后才被 finish 读）
    up_wait_max: u32 = 0,
    down_wait_max: u32 = 0,
    up_wr_max: u32 = 0,
    down_wr_max: u32 = 0,

    // ---------------- 生命周期 ----------------

    /// 连接建立（TCP accept 之后 / KCP 会话建立之后）。logger 为 null 或
    /// `log.trace=off` 时整个对象退化为空壳，所有方法立即返回。
    pub fn init(
        logger: *applog.Logger,
        transport: Transport,
        protocol: []const u8,
        source: []const u8,
        tag: []const u8,
    ) Trace {
        var tr = Trace{
            .logger = logger,
            .t0 = sys.nowMonoMs(),
            .transport = transport,
            .protocol = protocol,
        };
        // 身份字段无条件落（两次 memcpy，代价可忽略）：关闭时对象仍自洽，
        // 便于排障期动态开启/单测构造
        copyInto(&tr.source, &tr.source_len, source);
        copyInto(&tr.tag, &tr.tag_len, tag);
        tr.enabled = logger.enabled and logger.trace_level != .off;
        tr.full = tr.enabled and logger.trace_level == .full;
        if (!tr.enabled) return tr;
        tr.id = allocId();
        _ = agg.conns.fetchAdd(1, .monotonic);
        tr.detail("ev=accept", .{});
        return tr;
    }

    /// mux 子会话：继承父连接的身份字段，单独成行；字节量回灌父连接汇总。
    pub fn initChild(self: *Trace, sid: u16, dest_text: []const u8) Trace {
        var tr = Trace{
            .logger = self.logger,
            .enabled = self.enabled,
            .full = self.full,
            .t0 = sys.nowMonoMs(),
            .transport = self.transport,
            .protocol = self.protocol,
            .is_session = true,
            .sid = sid,
        };
        if (!tr.enabled) return tr;
        tr.parent = self;
        tr.id = self.id;
        tr.source = self.source;
        tr.source_len = self.source_len;
        tr.tag = self.tag;
        tr.tag_len = self.tag_len;
        tr.user = self.user;
        tr.user_len = self.user_len;
        copyInto(&tr.dest, &tr.dest_len, dest_text);
        _ = self.mux_sessions.fetchAdd(1, .monotonic);
        tr.detail("ev=session_new", .{});
        return tr;
    }

    pub fn getSource(self: *const Trace) []const u8 {
        return self.source[0..self.source_len];
    }

    pub fn getTag(self: *const Trace) []const u8 {
        return self.tag[0..self.tag_len];
    }

    pub fn getUser(self: *const Trace) []const u8 {
        return self.user[0..self.user_len];
    }

    pub fn getDest(self: *const Trace) []const u8 {
        return self.dest[0..self.dest_len];
    }

    pub fn getReason(self: *const Trace) Reason {
        // setReason 只写合法变体；fromInt 仅作并发读兜底（未知值 → unknown）
        return std.enums.fromInt(Reason, self.reason.load(.monotonic)) orelse .unknown;
    }

    /// 最后写入者胜出：最贴近关闭时刻的原因最具解释力
    pub fn setReason(self: *Trace, r: Reason) void {
        if (!self.enabled) return;
        self.reason.store(@intFromEnum(r), .monotonic);
    }

    // ---------------- 阶段打点 ----------------

    pub fn markWs(self: *Trace, ms: i64) void {
        if (!self.enabled) return;
        self.ws_ms = ms;
        if (ms >= slow_ws_ms) self.warn("ws", ms);
        self.detail("ev=ws ms={d}", .{ms});
    }

    /// 协议头首字节到达（相对流就绪）
    pub fn markHeaderWait(self: *Trace, ms: i64) void {
        if (!self.enabled) return;
        self.hdr_wait_ms = ms;
        if (ms >= slow_hdr_wait_ms) self.warn("hdr_wait", ms);
        self.detail("ev=hdr_first ms={d}", .{ms});
    }

    /// 头解析完成（服务端 CPU 成本）+ 身份字段
    pub fn markHeaderDone(self: *Trace, ms: i64, user: []const u8, cmd: u8, dest_text: []const u8) void {
        if (!self.enabled) return;
        self.hdr_parse_ms = ms;
        copyInto(&self.user, &self.user_len, user);
        copyInto(&self.dest, &self.dest_len, dest_text);
        // Mux 帧不带地址段 → dest 为空，此时不打 dest=（避免出现空的 dest= 尾巴）
        if (dest_text.len > 0) {
            self.detail("ev=hdr_done ms={d} user={s} cmd={d} dest={s}", .{ ms, user, cmd, dest_text });
        } else {
            self.detail("ev=hdr_done ms={d} user={s} cmd={d}", .{ ms, user, cmd });
        }
    }

    /// 出站拨号完成（含 DNS / 重试总耗时）
    pub fn markDial(self: *Trace, ms: i64, to: []const u8) void {
        if (!self.enabled) return;
        self.dial_ms = ms;
        if (ms >= slow_dial_ms) self.warn("dial", ms);
        self.detail("ev=dial ms={d} to={s}", .{ ms, to });
    }

    // ---------------- 数据面 ----------------

    /// 一个方向的读写记账。up = 客户端→远端，down = 远端→客户端。
    /// wait_ms = 数据到达前在 read 上等的时长（超时切片不计，故只在 n>0 时记）；
    /// wr_ms = 本次 writeAll 的阻塞时长（背压证据）。
    pub fn onData(self: *Trace, up: bool, n: usize, wait_ms: u32, wr_ms: u32) void {
        if (!self.enabled or n == 0) return;
        const nb: u64 = @intCast(n);
        const now = sys.nowMonoMs();
        if (up) {
            _ = self.up_bytes.fetchAdd(nb, .monotonic);
            _ = self.up_chunks.fetchAdd(1, .monotonic);
            if (wait_ms > self.up_wait_max) self.up_wait_max = wait_ms;
            if (wr_ms > self.up_wr_max) self.up_wr_max = wr_ms;
            if (self.up_first_ms < 0) {
                self.up_first_ms = now - self.t0;
                self.detail("ev=up_first ms={d} n={d}", .{ self.up_first_ms, n });
            }
        } else {
            _ = self.down_bytes.fetchAdd(nb, .monotonic);
            _ = self.down_chunks.fetchAdd(1, .monotonic);
            if (wait_ms > self.down_wait_max) self.down_wait_max = wait_ms;
            if (wr_ms > self.down_wr_max) self.down_wr_max = wr_ms;
            if (self.down_first_ms < 0) {
                self.down_first_ms = now - self.t0;
                self.detail("ev=down_first ms={d} n={d}", .{ self.down_first_ms, n });
            }
        }
        if (wr_ms >= slow_write_ms) self.warn(if (up) "up_write" else "down_write", wr_ms);
        self.last_act.store(now, .monotonic);
    }

    /// mux 子会话结束后把字节/块数并回父连接
    ///（父连接汇总 = 整条 TCP 的真实总量；块数一并并回，避免"有字节无块数"的怪行）
    pub fn addChild(self: *Trace, up: u64, down: u64, up_chunks: u32, down_chunks: u32) void {
        if (!self.enabled) return;
        if (up > 0) _ = self.up_bytes.fetchAdd(up, .monotonic);
        if (down > 0) _ = self.down_bytes.fetchAdd(down, .monotonic);
        if (up_chunks > 0) _ = self.up_chunks.fetchAdd(up_chunks, .monotonic);
        if (down_chunks > 0) _ = self.down_chunks.fetchAdd(down_chunks, .monotonic);
        self.last_act.store(sys.nowMonoMs(), .monotonic);
    }

    // ---------------- 收尾 ----------------

    /// 输出汇总行（幂等：重复调用只生效一次）。必须在两个拷贝线程都 join 之后调。
    pub fn finish(self: *Trace) void {
        if (!self.enabled) return;
        if (self.finished.swap(true, .monotonic)) return;

        const dur = sys.nowMonoMs() - self.t0;
        if (self.parent) |p| p.addChild(
            self.up_bytes.load(.monotonic),
            self.down_bytes.load(.monotonic),
            self.up_chunks.load(.monotonic),
            self.down_chunks.load(.monotonic),
        );
        aggRecord(self, dur);

        var buf: [summary_max]u8 = undefined;
        const line = self.formatSummary(&buf, dur);
        if (self.logger) |lg| lg.traceInfo(line);
    }

    /// 汇总行（纯格式化，无 IO —— 单测直接断言）
    pub fn formatSummary(self: *Trace, out: []u8, dur: i64) []const u8 {
        var o = Out{ .buf = out };
        if (self.is_session) {
            o.print("trace session conn={d} sid={d}", .{ self.id, self.sid });
        } else {
            o.print("trace conn={d}", .{self.id});
        }
        o.print(" reason={s} dur_ms={d}", .{ @tagName(self.getReason()), dur });
        o.print(" from={s} tag={s} tr={s} proto={s}", .{
            self.getSource(), self.getTag(), self.transport.tag(), self.protocol,
        });
        if (self.user_len > 0) o.print(" user={s}", .{self.getUser()});
        if (self.dest_len > 0) o.print(" dest={s}", .{self.getDest()});
        if (self.ws_ms >= 0) o.print(" ws_ms={d}", .{self.ws_ms});
        if (self.hdr_wait_ms >= 0) o.print(" hdr_wait_ms={d}", .{self.hdr_wait_ms});
        if (self.hdr_parse_ms >= 0) o.print(" hdr_parse_ms={d}", .{self.hdr_parse_ms});
        if (self.dial_ms >= 0) o.print(" dial_ms={d}", .{self.dial_ms});
        if (self.up_first_ms >= 0) o.print(" ttfub_ms={d}", .{self.up_first_ms});
        if (self.down_first_ms >= 0) o.print(" ttfb_ms={d}", .{self.down_first_ms});
        o.print(" up={d} down={d} up_chunks={d} down_chunks={d}", .{
            self.up_bytes.load(.monotonic), self.down_bytes.load(.monotonic),
            self.up_chunks.load(.monotonic), self.down_chunks.load(.monotonic),
        });
        if (self.up_wait_max > 0) o.print(" up_wait_ms={d}", .{self.up_wait_max});
        if (self.down_wait_max > 0) o.print(" down_wait_ms={d}", .{self.down_wait_max});
        if (self.up_wr_max > 0) o.print(" up_wr_ms={d}", .{self.up_wr_max});
        if (self.down_wr_max > 0) o.print(" down_wr_ms={d}", .{self.down_wr_max});
        const la = self.last_act.load(.monotonic);
        const idle: i64 = if (la > 0 and la >= self.t0) @max(0, dur - (la - self.t0)) else dur;
        o.print(" idle_ms={d}", .{idle});
        const mux = self.mux_sessions.load(.monotonic);
        if (mux > 0) o.print(" mux={d}", .{mux});
        return o.text();
    }

    // ---------------- 内部 ----------------

    fn warn(self: *Trace, stage: []const u8, ms: i64) void {
        const lg = self.logger orelse return;
        var b: [224]u8 = undefined;
        const m = if (self.is_session)
            std.fmt.bufPrint(&b, "trace slow conn={d} sid={d} stage={s} ms={d} from={s} tag={s}", .{
                self.id, self.sid, stage, ms, self.getSource(), self.getTag(),
            }) catch return
        else
            std.fmt.bufPrint(&b, "trace slow conn={d} stage={s} ms={d} from={s} tag={s}", .{
                self.id, stage, ms, self.getSource(), self.getTag(),
            }) catch return;
        lg.warning(m);
    }

    /// 阶段明细行：mux 子会话带 sid（同一父连接下多会话并发，不带 sid 无法归因）
    fn detail(self: *Trace, comptime fmt: []const u8, args: anytype) void {
        if (!self.full) return;
        const lg = self.logger orelse return;
        var b: [288]u8 = undefined;
        const head = if (self.is_session)
            std.fmt.bufPrint(&b, "trace conn={d} sid={d} ", .{ self.id, self.sid }) catch return
        else
            std.fmt.bufPrint(&b, "trace conn={d} ", .{self.id}) catch return;
        const rest = std.fmt.bufPrint(b[head.len..], fmt, args) catch return;
        lg.traceDetail(b[0..head.len + rest.len]);
    }
};

/// 热路径取时点：未开打点时连时钟都不读（返回 0，调用方据此跳过记账）。
pub fn stamp(tr: ?*Trace) i64 {
    const t = tr orelse return 0;
    if (!t.enabled) return 0;
    return sys.nowMonoMs();
}

// ============================ 进程级聚合（selfcheck 输出） ============================

/// 进程生命周期累计量：给 `selfcheck` 每 60s 一行趋势，避免逐连接翻日志。
pub const Aggregate = struct {
    conns: std.atomic.Value(u64) = .init(0),
    mux_conns: std.atomic.Value(u64) = .init(0),
    rejected: std.atomic.Value(u64) = .init(0),
    overload: std.atomic.Value(u64) = .init(0),
    ws_fail: std.atomic.Value(u64) = .init(0),
    hdr_fail: std.atomic.Value(u64) = .init(0),
    dial_fail: std.atomic.Value(u64) = .init(0),
    sum_dur: std.atomic.Value(u64) = .init(0),
    max_dur: std.atomic.Value(u64) = .init(0),
    n_hdr: std.atomic.Value(u64) = .init(0),
    sum_hdr: std.atomic.Value(u64) = .init(0),
    max_hdr: std.atomic.Value(u64) = .init(0),
    n_ttfb: std.atomic.Value(u64) = .init(0),
    sum_ttfb: std.atomic.Value(u64) = .init(0),
    max_ttfb: std.atomic.Value(u64) = .init(0),
};

pub var agg: Aggregate = .{};

fn atomicMax(v: *std.atomic.Value(u64), x: u64) void {
    var cur = v.load(.monotonic);
    while (x > cur) {
        if (v.cmpxchgWeak(cur, x, .monotonic, .monotonic)) |actual| {
            cur = actual;
        } else return;
    }
}

fn toU64(v: i64) u64 {
    return if (v > 0) @intCast(v) else 0;
}

fn aggRecord(tr: *Trace, dur: i64) void {
    if (tr.is_session) return; // 会话级不重复计入连接数
    const d = toU64(dur);
    _ = agg.sum_dur.fetchAdd(d, .monotonic);
    atomicMax(&agg.max_dur, d);
    if (tr.mux_sessions.load(.monotonic) > 0) _ = agg.mux_conns.fetchAdd(1, .monotonic);
    if (tr.hdr_wait_ms >= 0) {
        const h = toU64(tr.hdr_wait_ms);
        _ = agg.n_hdr.fetchAdd(1, .monotonic);
        _ = agg.sum_hdr.fetchAdd(h, .monotonic);
        atomicMax(&agg.max_hdr, h);
    }
    if (tr.down_first_ms >= 0) {
        const t = toU64(tr.down_first_ms);
        _ = agg.n_ttfb.fetchAdd(1, .monotonic);
        _ = agg.sum_ttfb.fetchAdd(t, .monotonic);
        atomicMax(&agg.max_ttfb, t);
    }
}

/// 拒绝/失败计数（在事件发生点单独累加，不受连接是否 init 影响）
pub fn countRejected() void {
    _ = agg.rejected.fetchAdd(1, .monotonic);
}

pub fn countWsFail() void {
    _ = agg.ws_fail.fetchAdd(1, .monotonic);
}

pub fn countHdrFail() void {
    _ = agg.hdr_fail.fetchAdd(1, .monotonic);
}

pub fn countDialFail() void {
    _ = agg.dial_fail.fetchAdd(1, .monotonic);
}

/// 并发上限拒绝（§3.5 overload）
pub fn countOverload() void {
    _ = agg.overload.fetchAdd(1, .monotonic);
}

/// 一行聚合（selfcheck 每 60s 调一次；无连接则不打）
pub fn emitAggregate(logger: *applog.Logger) void {
    if (!logger.enabled or logger.trace_level == .off) return;
    var b: [512]u8 = undefined;
    const line = formatAggregate(&b) orelse return;
    logger.traceInfo(line);
}

/// 聚合行格式化（纯函数，单测直接断言）；无连接样本时返回 null
pub fn formatAggregate(b: []u8) ?[]const u8 {
    const conns = agg.conns.load(.monotonic);
    if (conns == 0) return null;
    const n_hdr = agg.n_hdr.load(.monotonic);
    const n_ttfb = agg.n_ttfb.load(.monotonic);
    return std.fmt.bufPrint(
        b,
        "trace_stats conns={d} mux={d} rejected={d} overload={d} ws_fail={d} hdr_fail={d} dial_fail={d} dur_avg_ms={d} dur_max_ms={d} hdr_avg_ms={d} hdr_max_ms={d} ttfb_avg_ms={d} ttfb_max_ms={d}",
        .{
            conns,
            agg.mux_conns.load(.monotonic),
            agg.rejected.load(.monotonic),
            agg.overload.load(.monotonic),
            agg.ws_fail.load(.monotonic),
            agg.hdr_fail.load(.monotonic),
            agg.dial_fail.load(.monotonic),
            agg.sum_dur.load(.monotonic) / conns,
            agg.max_dur.load(.monotonic),
            if (n_hdr > 0) agg.sum_hdr.load(.monotonic) / n_hdr else 0,
            agg.max_hdr.load(.monotonic),
            if (n_ttfb > 0) agg.sum_ttfb.load(.monotonic) / n_ttfb else 0,
            agg.max_ttfb.load(.monotonic),
        },
    ) catch null;
}

// ============================ 测试 ============================

test "trace: off 时全部方法空转（不分配 id、不累加聚合）" {
    var lg = applog.Logger{ .enabled = true, .trace_level = .off };
    var tr = Trace.init(&lg, .websocket, "vless", "1.2.3.4:5", "inbound");
    try std.testing.expect(!tr.enabled);
    try std.testing.expectEqual(@as(u64, 0), tr.id);
    tr.markWs(9999); // 超阈值也不告警（logger 未开 trace）
    tr.onData(true, 100, 0, 0);
    tr.setReason(.eof);
    try std.testing.expectEqual(Reason.unknown, tr.getReason());
    try std.testing.expectEqual(@as(u64, 0), tr.up_bytes.load(.monotonic));
    tr.finish(); // 幂等且不 panic
    tr.finish();
}

/// 测试用：强制开启记录（`logger.enabled=false` 保证 emit 被拦、不落盘）。
/// init 时未启用 → 不分配 id（保持 0），故断言里的 conn=0 是确定值。
fn mkTrace(lg: *applog.Logger, transport: Transport, proto: []const u8, src: []const u8, tag: []const u8) Trace {
    var tr = Trace.init(lg, transport, proto, src, tag);
    tr.enabled = true;
    return tr;
}

test "trace: 启用时分配递增连接号" {
    var lg = applog.Logger{ .enabled = true, .trace_level = .summary };
    const a = Trace.init(&lg, .tcp, "vless", "1.1.1.1:1", "t");
    const b = Trace.init(&lg, .tcp, "vless", "1.1.1.1:2", "t");
    try std.testing.expect(a.id > 0);
    try std.testing.expectEqual(a.id + 1, b.id);
}

test "trace: summary 行字段顺序与取值" {
    var lg = applog.Logger{ .enabled = false, .trace_level = .summary };
    var tr = mkTrace(&lg, .websocket, "vless", "192.168.1.23:51234", "inbound-19001");
    tr.markWs(2);
    tr.markHeaderWait(38);
    tr.markHeaderDone(0, "pb8lpgli", 1, "www.google.com:443");
    tr.markDial(12, "142.250.1.1:443");
    tr.onData(true, 1024, 5, 0);
    tr.onData(false, 4096, 7, 0);
    tr.setReason(.eof);

    var buf: [summary_max]u8 = undefined;
    const line = tr.formatSummary(&buf, 18432);
    const want =
        "trace conn=0 reason=eof dur_ms=18432 from=192.168.1.23:51234 tag=inbound-19001 " ++
        "tr=ws proto=vless user=pb8lpgli dest=www.google.com:443 ws_ms=2 hdr_wait_ms=38 " ++
        "hdr_parse_ms=0 dial_ms=12 ttfub_ms=0 ttfb_ms=0 up=1024 down=4096 up_chunks=1 " ++
        "down_chunks=1 up_wait_ms=5 down_wait_ms=7 idle_ms=18432";
    try std.testing.expectEqualStrings(want, line);
}

test "trace: 未到达阶段整段省略（拒绝连接不出现 dial/ttfb）" {
    var lg = applog.Logger{ .enabled = false, .trace_level = .summary };
    var tr = mkTrace(&lg, .tcp, "vless", "10.0.0.9:1000", "t");
    tr.setReason(.rejected);
    var buf: [summary_max]u8 = undefined;
    const line = tr.formatSummary(&buf, 3);
    try std.testing.expectEqualStrings(
        "trace conn=0 reason=rejected dur_ms=3 from=10.0.0.9:1000 tag=t tr=tcp proto=vless " ++
            "up=0 down=0 up_chunks=0 down_chunks=0 idle_ms=3",
        line,
    );
    try std.testing.expect(std.mem.indexOf(u8, line, "dial_ms") == null);
}

test "trace: mux 子会话回灌父连接 + 汇总计数" {
    var lg = applog.Logger{ .enabled = false, .trace_level = .summary };
    var parent = mkTrace(&lg, .websocket, "vless", "1.1.1.1:2", "t");
    parent.markHeaderDone(0, "u", 3, "a.com:443");

    var c1 = parent.initChild(7, "a.com:443");
    c1.onData(true, 100, 1, 0);
    c1.onData(false, 900, 1, 0);
    c1.setReason(.eof);
    c1.finish();
    try std.testing.expectEqual(@as(u32, 1), parent.mux_sessions.load(.monotonic));

    var c2 = parent.initChild(8, "b.com:53");
    c2.onData(true, 50, 1, 0);
    c2.setReason(.eof);
    c2.finish();

    try std.testing.expectEqual(@as(u64, 150), parent.up_bytes.load(.monotonic));
    try std.testing.expectEqual(@as(u64, 900), parent.down_bytes.load(.monotonic));

    var buf: [summary_max]u8 = undefined;
    const line = parent.formatSummary(&buf, 1000);
    try std.testing.expect(std.mem.indexOf(u8, line, " up=150 down=900 ") != null);
    try std.testing.expect(std.mem.indexOf(u8, line, " mux=2") != null);
}

test "trace: 子会话行带 conn/sid 前缀且不重复计入 conns 聚合" {
    var lg = applog.Logger{ .enabled = false, .trace_level = .summary };
    var parent = mkTrace(&lg, .websocket, "vless", "1.1.1.1:2", "t");
    const conns_before = agg.conns.load(.monotonic);
    var c = parent.initChild(3, "x.com:443");
    c.setReason(.eof);
    c.finish();
    try std.testing.expectEqual(conns_before, agg.conns.load(.monotonic));

    var buf: [summary_max]u8 = undefined;
    const line = c.formatSummary(&buf, 9);
    try std.testing.expect(std.mem.startsWith(u8, line, "trace session conn="));
    try std.testing.expect(std.mem.indexOf(u8, line, " sid=3") != null);
}

test "trace: finish 幂等（只输出一次，聚合只记一次）" {
    var lg = applog.Logger{ .enabled = false, .trace_level = .summary };
    var tr = mkTrace(&lg, .tcp, "vless", "1.1.1.1:1", "t");
    tr.finish();
    tr.finish();
    var buf: [summary_max]u8 = undefined;
    _ = tr.formatSummary(&buf, 1);
    try std.testing.expect(tr.finished.load(.monotonic));
}

test "trace: 慢路径阈值触发 warning（不依赖 full）" {
    // logger 输出被 enabled=false 拦掉，但阈值判定分支必须走到（结构断言）
    var lg = applog.Logger{ .enabled = false, .trace_level = .summary };
    var tr = mkTrace(&lg, .tcp, "vless", "1.1.1.1:1", "t");
    tr.markWs(slow_ws_ms);
    tr.markHeaderWait(slow_hdr_wait_ms + 1);
    tr.markDial(slow_dial_ms, "1.2.3.4:443");
    try std.testing.expectEqual(slow_ws_ms, tr.ws_ms);
    try std.testing.expectEqual(slow_hdr_wait_ms + 1, tr.hdr_wait_ms);
    try std.testing.expectEqual(slow_dial_ms, tr.dial_ms);
}

test "trace: onData 忽略零长；wait/wr 取最大值" {
    var lg = applog.Logger{ .enabled = false, .trace_level = .summary };
    var tr = mkTrace(&lg, .tcp, "vless", "1.1.1.1:1", "t");
    tr.onData(true, 0, 99, 99); // n==0 不计
    try std.testing.expectEqual(@as(u64, 0), tr.up_bytes.load(.monotonic));
    tr.onData(true, 10, 5, 1);
    tr.onData(true, 10, 30, 9);
    tr.onData(true, 10, 20, 3);
    try std.testing.expectEqual(@as(u32, 3), tr.up_chunks.load(.monotonic));
    try std.testing.expectEqual(@as(u32, 30), tr.up_wait_max);
    try std.testing.expectEqual(@as(u32, 9), tr.up_wr_max);
}

test "trace: emitAggregate 无连接时不打；有连接时格式固定" {
    var lg = applog.Logger{ .enabled = false, .trace_level = .summary };
    emitAggregate(&lg); // 已有连接时也只是被 logger 拦掉，不 panic
}

test "trace: 聚合行字段齐全（trace_stats 一行趋势）" {
    _ = agg.conns.fetchAdd(1, .monotonic); // 聚合是进程级累计，保证有样本
    var lg = applog.Logger{ .enabled = false };
    var tr = mkTrace(&lg, .websocket, "vless", "1.1.1.1:1", "t");
    tr.markHeaderWait(40);
    tr.markDial(3, "1.1.1.1:443");
    tr.onData(false, 2048, 1, 0);
    tr.setReason(.eof);
    tr.finish();

    var b: [512]u8 = undefined;
    const line = formatAggregate(&b) orelse return error.NoAggregate;
    try std.testing.expect(std.mem.startsWith(u8, line, "trace_stats conns="));
    const keys = [_][]const u8{
        " conns=",      " mux=",       " rejected=",   " overload=",    " ws_fail=",
        " hdr_fail=",   " dial_fail=", " dur_avg_ms=", " dur_max_ms=",  " hdr_avg_ms=",
        " hdr_max_ms=", " ttfb_avg_ms=", " ttfb_max_ms=",
    };
    for (keys) |k| try std.testing.expect(std.mem.indexOf(u8, line, k) != null);
}
