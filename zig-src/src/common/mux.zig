//! mux v1 服务端（§9 扩展点；对照上游 common/mux/{frame,server,session,writer,reader}.go）。
//!
//! 线格式（每个 mux 帧）：
//!   [2B metaLen][metaLen 字节 meta][2B dataLen][dataLen 字节 payload]
//! meta = [2B sessionID][1B status][1B option][New 时: 1B network + port(2B) + address]
//! status: 1=New 2=Keep 3=End 4=KeepAlive；option bit0=OptionData（置位时后随 dataLen+payload）
//! 注意 End/KeepAlive 与空 Write 都是 meta-only（无 dataLen 段）。
//!
//! 服务端模型（对照 ServerWorker）：
//!   - 主循环读帧：New → 建 Session（两条内存管道）+ dispatch 到出站（独立线程）；
//!     Keep/New 带 OptionData → 载荷写入该 Session 的上行管道；End → 关上行管道（EOF）。
//!   - 每个 Session 一个 writer 线程：下行管道 → mux 帧，**一律 Keep + OptionData**
//!     （⚠️ 不能发 New：客户端 handleStatusNew 对带数据的帧直接 discard，见 M13 互通排障）。
//!     收尾发 End 帧。
//!   - 60s 无会话且无新增 → 主动结束整条 mux 连接（上游 CloseIfNoSessionAndIdle）。
//!   - 退出前必须 closeAll + waitInflight：会话线程持有上层 arena，提前返回即 UAF（M20）。
//!
//! 传输面：TCP（Stream）与 XUDP（New 帧带 GlobalID + UDP 目标，packet_mode 按包边界搬运）。
//! 内存管道 Pipe 用 futex 事件序号阻塞（M21，替代 1ms 轮询）。

const std = @import("std");
const linux = std.os.linux;
const sys = @import("../common/sys.zig");
const sock_mod = @import("../common/sock.zig");
const net = @import("../common/net.zig");
const addr = @import("../common/addr.zig");
const buf = @import("../common/buf.zig");
const stream_mod = @import("../core/stream.zig");
const applog = @import("../app/log.zig");
const dispatcher_mod = @import("../app/dispatcher.zig");
const udp_pkt = @import("../proxy/udp_packet.zig");

pub const STATUS_NEW: u8 = 0x01;
pub const STATUS_KEEP: u8 = 0x02;
pub const STATUS_END: u8 = 0x03;
pub const STATUS_KEEP_ALIVE: u8 = 0x04;

pub const OPTION_DATA: u8 = 0x01;
pub const OPTION_ERROR: u8 = 0x02;

pub const TARGET_NETWORK_TCP: u8 = 0x01;
pub const TARGET_NETWORK_UDP: u8 = 0x02;

/// 上游 FrameMetadata.Unmarshal：metaLen > 512 拒绝
pub const MAX_META_LEN: usize = 512;
/// 下行批量：DownWriter 一次读满这么多再组一个 mux 帧。
/// M23 修正：M22 测 8KB vs 32KB 无差异，是因为**数据源（freedom）每次只写 8KB**，
/// 管道里根本没有 32KB 可读——批量形同虚设。freedom 同步改成 32KB 栈缓冲后，
/// 这里必须一起改成 32KB 才真正生效（帧数 128→32，futex 唤醒同比减少）。
const down_batch_size: usize = 32 * 1024;
/// 上游 buf.Size：单帧载荷上限 8KB
pub const MAX_FRAME_DATA: usize = 8 * 1024;

pub const MuxError = error{
    TruncatedMeta,
    MetaTooLong,
    BadStatus,
    UnknownNetwork,
    UnsupportedNetwork, // Phase 2-lite：UDP 目标
    BadAddress,
    FrameTooBig,
    ReadFailed,
    StreamClosed,
    OutOfMemory,
};

// ============================ 内存管道 ============================

/// 单写单读内存管道（对应 transport/pipe；本实现无大小上限，与上游
/// OptionsFromContext 默认的 WithoutSizeLimit 一致；背压由对端 TCP 流控承担）。
pub const Pipe = struct {
    mu: sys.Mutex = .{},
    data: std.ArrayList(u8) = .empty,
    write_closed: bool = false,
    read_closed: bool = false,
    /// 事件序号（M21）：写入/关闭时递增并 futex 唤醒读者。
    /// 用「序号快照 + FUTEX_WAIT(expected)」而不是布尔标志，天然免疫「检查后睡前」丢唤醒
    ///（M9 三态互斥锁的孤儿等待者教训）；同时保留 1s 超时兜底，不依赖唤醒必达。
    /// 替代 M20 之前的 1ms 轮询——XUDP 长会话下 14 个线程空转 0.4% 单核是纯浪费。
    seq: std.atomic.Value(u32) = .init(0),

    pub fn init() Pipe {
        return .{};
    }

    pub fn deinit(self: *Pipe, allocator: std.mem.Allocator) void {
        self.data.deinit(allocator);
    }

    /// 唤醒所有阻塞读者（调用方不得持有 mu，否则 unlock 前 wake 会丢）
    fn wake(self: *Pipe) void {
        _ = self.seq.fetchAdd(1, .release);
        _ = linux.futex(&self.seq.raw, .{ .cmd = .WAKE, .private = false }, std.math.maxInt(u32), .{ .val2 = 0 }, null, 0);
    }

    /// 读侧：返回 0 = EOF（写侧关闭）。阻塞直到有数据或关闭。
    pub fn read(self: *Pipe, out: []u8) anyerror!usize {
        while (true) {
            // 快照必须在「查数据」之前：若写入发生在这两步之间，seq 已变，
            // 下一次 FUTEX_WAIT 的 expected 不匹配 → 立即 EAGAIN 返回，不睡死。
            const snapshot = self.seq.load(.acquire);
            self.mu.lock();
            if (self.data.items.len > 0) {
                const n = @min(out.len, self.data.items.len);
                @memcpy(out[0..n], self.data.items[0..n]);
                std.mem.copyForwards(u8, self.data.items[0 .. self.data.items.len - n], self.data.items[n..]);
                self.data.shrinkRetainingCapacity(self.data.items.len - n);
                self.mu.unlock();
                return n;
            }
            // 写侧关闭（对端 EOF）或读侧被放弃 → 读侧看到 EOF
            if (self.write_closed or self.read_closed) {
                self.mu.unlock();
                return 0;
            }
            self.mu.unlock();
            // 1s 超时兜底：即使极端情况下丢唤醒，也能在一个 tick 内恢复
            const ts: linux.timespec = .{ .sec = 1, .nsec = 0 };
            _ = linux.futex(&self.seq.raw, .{ .cmd = .WAIT, .private = false }, snapshot, .{ .timeout = &ts }, null, 0);
        }
    }

    /// 写侧：读侧已关 → error.StreamClosed（调用方应放弃该会话）
    pub fn writeAll(self: *Pipe, data: []const u8, allocator: std.mem.Allocator) anyerror!void {
        self.mu.lock();
        if (self.read_closed or self.write_closed) {
            self.mu.unlock();
            return error.StreamClosed;
        }
        self.data.appendSlice(allocator, data) catch {
            self.mu.unlock();
            return error.OutOfMemory;
        };
        self.mu.unlock();
        self.wake();
    }

    /// 写侧关闭 → 读侧看到 EOF
    pub fn closeWrite(self: *Pipe) void {
        self.mu.lock();
        self.write_closed = true;
        self.mu.unlock();
        self.wake();
    }

    /// 读侧关闭 → 写侧报错
    pub fn closeRead(self: *Pipe) void {
        self.mu.lock();
        self.read_closed = true;
        self.mu.unlock();
        self.wake();
    }
};

// ============================ 帧编解码 ============================

/// 帧 meta（对照 FrameMetadata；仅服务端需要的字段）
pub const FrameMeta = struct {
    session_id: u16,
    status: u8,
    option: u8,
    /// New 帧才有：network 字节（0 表示非 New 无目标）
    network: u8 = 0,
    target: ?net.Destination = null,
    /// XUDP 会话标识（上游 FrameMetadata.GlobalID）。仅当
    /// New + OptionData + UDP target 且 meta 剩余 >= 8 字节时存在。
    global_id: [8]u8 = @splat(0),
};

/// 从 meta 缓冲区解析（对照 UnmarshalFromBuffer，readSourceAndLocal=false）
pub fn parseMeta(b: []const u8) MuxError!FrameMeta {
    if (b.len < 4) return MuxError.TruncatedMeta;
    var m = FrameMeta{
        .session_id = std.mem.readInt(u16, b[0..2], .big),
        .status = b[2],
        .option = b[3],
    };
    // 上游 handleFrame：未知 status 报 "unknown status"
    switch (m.status) {
        STATUS_NEW, STATUS_KEEP, STATUS_END, STATUS_KEEP_ALIVE => {},
        else => return MuxError.BadStatus,
    }
    // 上游 UnmarshalFromBuffer：New 帧、或 Keep 帧且第 5 字节为 UDP 时带地址
    //（后者是 XUDP over mux 的形态）。
    //
    // M19：UDP 目标**照常解析**（不再在此报 UnsupportedNetwork）。原因：Xray 客户端
    // 对 UDP 流量默认走 XUDP over mux，若在解析层报错，serve 会 return 掉**整条**
    // mux 连接——连累同一连接上的所有 TCP 请求（实测日志：`mux: unsupported target
    // network, closing mux connection`，5/5 UDP 全超时）。改由 serve 按会话降级。
    const has_addr = m.status == STATUS_NEW or
        (m.status == STATUS_KEEP and b.len > 4 and b[4] == TARGET_NETWORK_UDP);
    var addr_end: usize = 0;
    if (has_addr) {
        if (b.len < 5) return MuxError.TruncatedMeta;
        m.network = b[4];
        if (m.network != TARGET_NETWORK_TCP and m.network != TARGET_NETWORK_UDP) {
            return MuxError.UnknownNetwork;
        }
        var pos: usize = 5;
        var dest = addr.readPortThenAddress(b, &pos, null) catch return MuxError.BadAddress;
        dest.network = if (m.network == TARGET_NETWORK_UDP) .udp else .tcp;
        m.target = dest;
        addr_end = pos;
    }
    // 上游 Unmarshal 末尾：New + OptionData + UDP target + 剩余 >= 8 → GlobalID（XUDP）。
    // 注意"无 OptionData 的 New 帧没有 GlobalID"（客户端只在带首包时携带）。
    if (m.status == STATUS_NEW and (m.option & OPTION_DATA) != 0 and
        m.network == TARGET_NETWORK_UDP and b.len >= addr_end + 8)
    {
        @memcpy(m.global_id[0..8], b[addr_end..][0..8]);
    }
    return m;
}

/// 序列化 meta 到 out（返回写入长度）。
/// status 即最终 status；with_target=true 时才带目标地址（上游：仅 New 帧带）。
/// 对照 FrameMetadata.WriteTo（followup 只影响"是否首次"）与 NewResponseWriter。
pub fn writeMeta(
    out: []u8,
    session_id: u16,
    status: u8,
    option: u8,
    target: ?net.Destination,
    with_target: bool,
) MuxError!usize {
    if (out.len < 4) return MuxError.TruncatedMeta;
    var body: [MAX_META_LEN]u8 = undefined;
    var w: usize = 0;
    std.mem.writeInt(u16, body[0..2], session_id, .big);
    w += 2;
    body[w] = status;
    w += 1;
    body[w] = option;
    w += 1;
    if (with_target) {
        if (target) |t| {
            // mux meta 布局：[network(1)][port(2)][address]
            // writePortThenAddress 只写 port+address，network 字节需自己补
            body[w] = if (t.network == .udp) TARGET_NETWORK_UDP else TARGET_NETWORK_TCP;
            w += 1;
            w += addr.writePortThenAddress(body[w..], t);
        }
    } else if (status == STATUS_NEW) {
        return MuxError.TruncatedMeta; // New 帧必须带目标
    }
    // [2B metaLen][meta]
    std.mem.writeInt(u16, out[0..2], @intCast(w), .big);
    @memcpy(out[2..][0..w], body[0..w]);
    return 2 + w;
}

/// 组一个完整帧：[meta][2B dataLen][data]。返回总长度。
pub fn buildFrame(
    out: []u8,
    session_id: u16,
    status: u8,
    option: u8,
    target: ?net.Destination,
    with_target: bool,
    payload: []const u8,
) MuxError!usize {
    var n = try writeMeta(out, session_id, status, option, target, with_target);
    if (payload.len > 0) {
        if (n + 2 + payload.len > out.len) return MuxError.FrameTooBig;
        std.mem.writeInt(u16, out[n..][0..2], @intCast(payload.len), .big);
        n += 2;
        @memcpy(out[n..][0..payload.len], payload);
        n += payload.len;
    }
    return n;
}

/// 从流读恰好 n 字节（对应 ReadFullFrom）
fn readFull(s: stream_mod.Stream, out: []u8) MuxError!void {
    var off: usize = 0;
    while (off < out.len) {
        const n = s.read(out[off..]) catch return MuxError.ReadFailed;
        if (n == 0) return MuxError.StreamClosed;
        off += n;
    }
}

/// 读一个 u16（大端）
fn readU16(s: stream_mod.Stream) MuxError!u16 {
    var b: [2]u8 = undefined;
    try readFull(s, b[0..]);
    return std.mem.readInt(u16, b[0..2], .big);
}

// ============================ Pipe 的 Stream 适配 ============================

/// 把 Pipe 包成 Stream（ctx = *PipeCtx，持有 allocator 供写侧扩容）
pub const PipeCtx = struct {
    pipe: Pipe,
    alloc: std.mem.Allocator,
};

fn pipeRead(ctx: *anyopaque, out: []u8) anyerror!usize {
    const self: *PipeCtx = @ptrCast(@alignCast(ctx));
    return self.pipe.read(out);
}

fn pipeWriteAll(ctx: *anyopaque, data: []const u8) anyerror!void {
    const self: *PipeCtx = @ptrCast(@alignCast(ctx));
    return self.pipe.writeAll(data, self.alloc);
}

fn pipeClose(ctx: *anyopaque) void {
    const self: *PipeCtx = @ptrCast(@alignCast(ctx));
    self.pipe.closeRead();
}

fn pipeSetTimeout(_: *anyopaque, _: i64) void {} // 内存管道无超时语义

fn pipeShutdownWrite(ctx: *anyopaque) void {
    const self: *PipeCtx = @ptrCast(@alignCast(ctx));
    self.pipe.closeWrite();
}

pub fn pipeStream(self: *PipeCtx) stream_mod.Stream {
    return .{
        .ctx = self,
        .readFn = pipeRead,
        .writeAllFn = pipeWriteAll,
        .closeFn = pipeClose,
        .setTimeoutFn = pipeSetTimeout,
        .shutdownWriteFn = pipeShutdownWrite,
    };
}

// ============================ 服务端 ============================

/// 一个 mux 会话：上行 Pipe（mux 主循环 → 出站）+ 下行 Pipe（出站 → mux writer）
const Session = struct {
    id: u16,
    up: *PipeCtx, // 出站的 reader
    down: *PipeCtx, // 出站的 writer
    dead: bool = false,
};

const SessionManager = struct {
    mu: sys.Mutex = .{},
    map: std.AutoHashMapUnmanaged(u16, *Session) = .empty,
    /// 已创建过的会话总数（上游 count 字段）：idle 判定用
    total: u32 = 0,
    /// 在途会话线程数（serve 退出前必须归零，否则线程会用已释放的 arena）
    inflight: u32 = 0,
    closed: bool = false,

    fn add(self: *SessionManager, s: *Session, alloc: std.mem.Allocator) bool {
        self.mu.lock();
        defer self.mu.unlock();
        if (self.closed) return false;
        self.map.put(alloc, s.id, s) catch return false;
        self.total += 1;
        self.inflight += 2; // sessionMain + DownWriter 各占一份
        return true;
    }

    fn get(self: *SessionManager, id: u16) ?*Session {
        self.mu.lock();
        defer self.mu.unlock();
        return self.map.get(id);
    }

    fn remove(self: *SessionManager, id: u16) void {
        self.mu.lock();
        defer self.mu.unlock();
        _ = self.map.remove(id);
    }

    /// 会话线程结束登记（sessionMain / DownWriter 退出时调用）
    fn leave(self: *SessionManager) void {
        self.mu.lock();
        defer self.mu.unlock();
        if (self.inflight > 0) self.inflight -= 1;
    }

    /// 阻塞等到在途会话线程全部结束。**无预算**——上层 arena 的 link.writer
    /// 要等这些线程用完才能释放，提前返回必然 UAF。
    fn waitInflight(self: *SessionManager) void {
        while (true) {
            self.mu.lock();
            const n = self.inflight;
            self.mu.unlock();
            if (n == 0) return;
            sys.sleepMs(5);
        }
    }

    /// 当前在途会话线程数（leave 归零即代表该连接的所有会话线程已结束）
    fn inflightNow(self: *SessionManager) u32 {
        self.mu.lock();
        defer self.mu.unlock();
        return self.inflight;
    }

    fn total_snapshot(self: *SessionManager) u32 {
        self.mu.lock();
        defer self.mu.unlock();
        return self.total;
    }

    fn size(self: *SessionManager) usize {
        self.mu.lock();
        defer self.mu.unlock();
        return self.map.count();
    }

    /// 上游 CloseIfNoSessionAndIdle：无会话、上一轮也无会话、且期间无新增 → true
    fn closeIfNoSessionAndIdle(self: *SessionManager, check_size: usize, check_total: u32) bool {
        self.mu.lock();
        defer self.mu.unlock();
        if (self.closed) return true;
        if (self.map.count() != 0 or check_size != 0 or check_total != self.total) return false;
        self.closed = true;
        self.map.clearRetainingCapacity();
        return true;
    }

    fn closeAll(self: *SessionManager) void {
        self.mu.lock();
        defer self.mu.unlock();
        var it = self.map.valueIterator();
        while (it.next()) |s| {
            s.*.dead = true;
            s.*.up.pipe.closeWrite(); // 上行 EOF → 出站拷贝线程收尾
            s.*.down.pipe.closeRead(); // 下行写失败 → writer 线程退出
        }
        self.map.clearRetainingCapacity();
    }
};

/// 下行 writer：把 Session 下行管道的数据组成 mux 帧写给客户端。
/// 对应上游 handle() + NewResponseWriter。
const DownWriter = struct {
    id: u16,
    out: stream_mod.Stream,
    down: *PipeCtx,
    mgr: ?*SessionManager = null,
    mu: sys.Mutex = .{},
    closed: bool = false,
    /// XUDP（Packet 传输类型）：管道里是 length-prefixed 包，帧 payload 只放**裸 UDP 数据**
    /// （上游 writeMetaWithFrame 的 dataLen 即包长，不含额外的长度前缀）。
    packet_mode: bool = false,

    /// 对应上游 handle() + NewResponseWriter：下行管道 → mux 帧；结束补 End 帧。
    /// **响应帧恒为 Keep**（NewResponseWriter 的 followup 初值 true → getNextFrameMeta
    /// 永远走 Keep 分支）：客户端 handleStatusNew 带 OptionData 会直接丢弃数据，
    /// 只有 handleStatusKeep 才写入会话——首帧用 New 是 M12 互通 0/12 的直接原因。
    fn run(self: *DownWriter) void {
        defer if (self.mgr) |m| m.leave();
        if (self.packet_mode) {
            // XUDP：按包边界读（freedom 的 UDP 写侧是 length-prefixed），
            // 去掉 2B 前缀后作为帧 payload（对齐上游 Packet 传输类型）
            var pb: [udp_pkt.MAX_PACKET]u8 = undefined;
            const src = pipeStream(self.down);
            while (true) {
                const pn = udp_pkt.readPacket(src, &pb) catch break;
                self.writeFrame(pb[0..pn]) catch break;
            }
        } else {
            // M22：一次读满 32KB 再组帧（原 8KB/帧）。弱网下减少帧数与 futex 唤醒次数，
            // 让 TCP 有更连续的发送流；dataLen 是 u16，32KB 远在限制内，客户端按 dataLen 读。
            var b: [down_batch_size]u8 = undefined;
            while (true) {
                const n = self.down.pipe.read(&b) catch break;
                if (n == 0) {
                    break;
                }
                self.writeFrame(b[0..n]) catch break;
            }
        }
        self.writeEnd() catch {};
    }

    fn writeFrame(self: *DownWriter, data: []const u8) !void {
        self.mu.lock();
        defer self.mu.unlock();
        if (self.closed) return error.StreamClosed;
        var fb: [MAX_META_LEN + 2 + down_batch_size]u8 = undefined;
        const n = try buildFrame(&fb, self.id, STATUS_KEEP, OPTION_DATA, null, false, data);
        try self.out.writeAll(fb[0..n]);
    }

    fn writeEnd(self: *DownWriter) !void {
        self.mu.lock();
        defer self.mu.unlock();
        if (self.closed) return;
        self.closed = true;
        var fb: [MAX_META_LEN + 2]u8 = undefined;
        const n = try buildFrame(&fb, self.id, STATUS_END, 0, null, false, "");
        try self.out.writeAll(fb[0..n]);
    }
};

/// 会话资源守护：serve 已返回但会话线程仍在跑（典型：dial 慢目标）时，
/// 由本线程等最后一条会话线程结束后释放 arena 与 mgr。
/// 对应上游"goroutine detach + GC 兜底"——不设超时预算，线程活多久就等多久。
/// 出站 dispatch 线程参数（每个 mux 会话一个）
const SessionJob = struct {
    dsp: *dispatcher_mod.Dispatcher,
    arena: std.mem.Allocator,
    sess: buf.Session,
    dest: net.Destination,
    link: stream_mod.Link,
    mgr: *SessionManager,
    logger: *applog.Logger,
    source: []const u8, // M28：客户端地址（复盘配对 from=）
    id: u16,
    up: *PipeCtx,
    down: *PipeCtx,
};

/// 对应上游 go handle(ctx, s, w.link.Writer) 里 dispatch 的那一半：
/// 阻塞地把该会话的上下行管道接到出站；返回后会话即宣告结束。
fn sessionMain(job: *SessionJob) void {
    // M12 排障：mux 会话生命周期（短命会话=客户端频繁建链的直接证据）
    //
    // ⚠️ 必须先把字段快照到栈上：defer 是 LIFO，日志块在 `mgr.leave()` **之后**执行，
    // 而 leave() 使 inflight 归零会让 serve 的 waitInflight 返回并释放 sess_arena——
    // `job` 本身就在该 arena 内。直接用 job.id/job.dest 是 use-after-free
    //（aarch64 ReleaseSafe 实测 SIGSEGV：mux session closed 打印后立刻崩溃）。
    const job_id = job.id;
    const job_dest_port = job.dest.port;
    const job_logger = job.logger;
    const job_source = job.source; // M28：同理必须快照（job 在 sess_arena 内）
    const started_ms = sys.nowMonoMs();
    defer {
        var lb: [160]u8 = undefined;
        if (std.fmt.bufPrint(&lb, "mux session closed: id={d} dest_port={d} from={s} duration={d}ms", .{ job_id, job_dest_port, job_source, sys.nowMonoMs() - started_ms })) |m| {
            job_logger.info(m);
        } else |_| {}
    }
    defer job.mgr.leave(); // 本会话及其 freedom 拷贝线程全部结束
    job.dsp.dispatch(job.arena, &job.sess, job.dest, job.link) catch {};
    // 出站结束 → 上行 EOF（唤醒还在读的上行拷贝）、下行写失败（writer 退出）
    job.up.pipe.closeWrite();
    // M20：下行写侧也必须由这里兜底关闭。正常路径由出站拷贝线程 shutdownWrite 传播
    //（freedom TCP/UDP 两条路径都有），但**不能依赖它**——一旦漏掉，DownWriter 会在
    // Pipe.read 里永久轮询，waitInflight 永不归零（XUDP 收尾实测就是这种悬挂）。
    // 这里关闭后 DownWriter 会先把管道里剩余数据写完，再补 End 帧退出。
    job.down.pipe.closeWrite();
    job.mgr.remove(job.id);
}

/// 服务端主入口（对照 ServerWorker.run + monitor）。
/// link = 协议载荷流（VLESS 明文 / VMess 分块体）；sess 提供 access 日志字段。
pub fn serve(
    arena: std.mem.Allocator,
    alloc: std.mem.Allocator,
    dsp: *dispatcher_mod.Dispatcher,
    sess: *const buf.Session,
    link: stream_mod.Link,
    logger: *applog.Logger,
    source: []const u8, // M28：客户端地址，用于会话关闭日志的 from=（复盘配对用）
) void {
    // 上游语义（server.go DispatchLink）：serve 只等 worker.done / ctx.Done()，
    // 会话 goroutine 全部 detach、**不等待**——Go 靠 GC 保证"对象活到最后一个
    // 引用它的 goroutine 结束"。Zig 无 GC，用等价手段：
    //   * 会话对象（管道/会话/writer/job）全部从 sess_arena 分配，mgr 也在 alloc 上；
    //   * serve 返回时 closeAll（对应上游 monitor 的 common.Interrupt：让在途
    //     拷贝立即返回），随后由守护线程等 inflight 归零才释放——
    //     等多久由线程自身决定（dial 慢目标时可能数十秒），不设预算。
    const mgr = alloc.create(SessionManager) catch return;
    mgr.* = .{};
    var sess_arena = std.heap.ArenaAllocator.init(alloc);
    const sess_alloc = sess_arena.allocator();
    // M28：source 拷进 sess_arena——job.source 被会话线程持有，必须比它们活得长
    // （connEntry 栈上的 src_buf 虽因 serve 同步等会话而事实上够长，但不依赖这点）
    const job_source = sess_alloc.dupe(u8, source) catch return;
    // 退出：closeAll 让在途拷贝立即返回，然后**必须阻塞等所有会话线程真正结束**。
    //
    // ⚠️ 为什么不能"提前返回 + 后台 drain"（M14 的 DrainGuard 方案已废弃）：
    // `link.writer` 是上层（connEntry / vmess 分块 AuthWriter）arena 上的对象，
    // 上层在 serve 返回后立刻 deinit 自己的 arena。若还有 DownWriter 在 writeEnd()
    // 里用该 writer，就是 use-after-free——aarch64 实测 SIGSEGV（core 栈：
    // AuthWriter.writeAll ← DownWriter.writeEnd ← DownWriter.run）。
    // Go 上游能 detach 是因为 GC 保证"对象活到最后一个引用者"，Zig 无 GC 只能等。
    defer {
        mgr.closeAll();
        mgr.waitInflight();
        sess_arena.deinit();
        alloc.destroy(mgr);
    }

    var idle_check_size: usize = 0;
    var idle_check_total: u32 = 0;

    // idle 节拍：底层流设 1s 读超时，超时即一次节拍（对照 monitor 的 60s ticker）
    link.reader.setTimeout(1000);
    var idle_ticks: u32 = 0;

    while (true) {
        const meta_len = readU16(link.reader) catch |e| {
            switch (e) {
                // 读超时 = idle 节拍；其他错误/EOF = 连接结束
                MuxError.ReadFailed => {
                    idle_ticks += 1;
                    if (idle_ticks >= 60) {
                        idle_ticks = 0;
                        if (mgr.closeIfNoSessionAndIdle(idle_check_size, idle_check_total)) return;
                        idle_check_size = mgr.size();
                        idle_check_total = mgr.total_snapshot();
                    }
                    continue;
                },
                else => return,
            }
        };
        idle_ticks = 0;
        if (meta_len == 0 or meta_len > MAX_META_LEN) return;
        var mb: [MAX_META_LEN]u8 = undefined;
        readFull(link.reader, mb[0..meta_len]) catch return;
        const meta = parseMeta(mb[0..meta_len]) catch |e| {
            switch (e) {
                // Phase 2-lite：UDP 目标按上游语义返回错误 → 断开整条 mux
                // UnsupportedNetwork 自 M19 起不再由 parseMeta 产生（UDP 改由会话级降级）
                MuxError.UnsupportedNetwork, MuxError.UnknownNetwork => {
                    logger.warning("mux: unsupported target network, closing mux connection");
                    return;
                },
                else => return,
            }
        };

        switch (meta.status) {
            STATUS_KEEP_ALIVE => {
                if (meta.option & OPTION_DATA != 0) discardPayload(link.reader) catch return;
            },
            STATUS_END => {
                if (mgr.get(meta.session_id)) |s| {
                    s.up.pipe.closeWrite(); // 上行 EOF
                    mgr.remove(meta.session_id);
                }
                if (meta.option & OPTION_DATA != 0) discardPayload(link.reader) catch return;
                // 上游语义：End 只是单会话收尾，主循环继续等下一帧。
                // 但若已无任何会话（且历史上创建过），客户端通常紧接着关 TCP，
                // 由读超时/idle 路径收尾；此处不主动退出，避免半开连接被误杀。
            },
            STATUS_NEW => {
                const dest = meta.target orelse return;
                // UDP 目标 = XUDP 会话（对照上游 handleStatusNew → dispatch 到 freedom
                // 的 Network_UDP 分支，管道里走 length-prefixed 包）。
                //
                // M20 已启用：互通（Go 客户端 UDP）与收尾悬挂修复后验证通过。
                // 保留开关是为了线上可一键回退到"会话级降级"（只回 End 帧，不建会话）。
                const xudp_enabled = true;
                const is_udp = dest.network == .udp and xudp_enabled;
                if (dest.network == .udp and !xudp_enabled) {
                    var eb: [MAX_META_LEN + 2]u8 = undefined;
                    if (buildFrame(&eb, meta.session_id, STATUS_END, 0, null, false, "")) |en| {
                        link.writer.writeAll(eb[0..en]) catch return;
                    } else |_| {}
                    if (meta.option & OPTION_DATA != 0) discardPayload(link.reader) catch return;
                    logger.debug("mux: udp session rejected (XUDP disabled), mux connection kept");
                    continue;
                }
                const up = sess_alloc.create(PipeCtx) catch return;
                up.* = .{ .pipe = Pipe.init(), .alloc = sess_alloc };
                const down = sess_alloc.create(PipeCtx) catch return;
                down.* = .{ .pipe = Pipe.init(), .alloc = sess_alloc };
                const s = sess_alloc.create(Session) catch return;
                s.* = .{ .id = meta.session_id, .up = up, .down = down };
                if (!mgr.add(s, arena)) return;
                {
                    // M12 排障：mux 会话建立
                    var lb: [160]u8 = undefined;
                    if (std.fmt.bufPrint(&lb, "mux session opened: id={d} dest_port={d} from={s}", .{ meta.session_id, dest.port, sess.getSource() })) |m| {
                        logger.info(m);
                    } else |_| {}
                }

                // 下行 writer 线程（对应 go handle）
                const dw = sess_alloc.create(DownWriter) catch return;
                dw.* = .{ .id = meta.session_id, .out = link.writer, .down = down, .mgr = mgr, .packet_mode = is_udp };
                const th = std.Thread.spawn(.{ .stack_size = sys.crypto_thread_stack }, DownWriter.run, .{dw}) catch return;
                th.detach();

                // 出站 dispatch 线程
                const job = sess_alloc.create(SessionJob) catch return;
                job.* = .{
                    .dsp = dsp,
                    .arena = sess_alloc,
                    .sess = sess.*,
                    .dest = dest,
                    .link = .{ .reader = pipeStream(up), .writer = pipeStream(down) },
                    .mgr = mgr,
                    .logger = logger,
                    .source = job_source,
                    .id = meta.session_id,
                    .up = up,
                    .down = down,
                };
                const th2 = std.Thread.spawn(.{ .stack_size = sys.crypto_thread_stack }, sessionMain, .{job}) catch return;
                th2.detach();

                // 上游 handleStatusNew：无 OptionData 时直接 return nil（**不发任何帧**），
                // 只有带首包才把数据转给出站。
                if (meta.option & OPTION_DATA != 0) {
                    const payload = readPayload(sess_alloc, link.reader) catch return;
                    if (is_udp) {
                        // mux 的 UDP 帧 payload 是**裸 UDP 数据**（dataLen 即包长），
                        // 而 freedom 的 UDP 管道用 length-prefixed，需补 2B 前缀。
                        var lb: [2]u8 = undefined;
                        std.mem.writeInt(u16, lb[0..2], @intCast(payload.len), .big);
                        up.pipe.writeAll(&lb, sess_alloc) catch {};
                    }
                    up.pipe.writeAll(payload, sess_alloc) catch {};
                }
            },
            STATUS_KEEP => {
                if (meta.option & OPTION_DATA == 0) continue;
                if (mgr.get(meta.session_id)) |s| {
                    const payload = readPayload(sess_alloc, link.reader) catch return;
                    s.up.pipe.writeAll(payload, sess_alloc) catch {};
                } else {
                    // 上游：未知会话 → 回 End 帧并丢弃载荷
                    var fb: [MAX_META_LEN + 2]u8 = undefined;
                    const n = buildFrame(&fb, meta.session_id, STATUS_END, 0, null, false, "") catch return;
                    link.writer.writeAll(fb[0..n]) catch return;
                    discardPayload(link.reader) catch return;
                }
            },
            else => return,
        }

    }
}

fn discardPayload(s: stream_mod.Stream) MuxError!void {
    const len = try readU16(s);
    if (len > MAX_FRAME_DATA) return MuxError.FrameTooBig;
    var b: [MAX_FRAME_DATA]u8 = undefined;
    try readFull(s, b[0..len]);
}

fn readPayload(arena: std.mem.Allocator, s: stream_mod.Stream) MuxError![]const u8 {
    const len = try readU16(s);
    if (len > MAX_FRAME_DATA) return MuxError.FrameTooBig;
    const out = arena.alloc(u8, len) catch return MuxError.OutOfMemory;
    errdefer arena.free(out);
    try readFull(s, out);
    return out;
}

// ============================ 测试 ============================

test "mux: 帧 roundtrip（New/Keep/End + OptionData）" {
    const dest = net.Destination{ .network = .tcp, .address = .{ .ipv4 = .{ 127, 0, 0, 1 } }, .port = 8080 };

    // New 帧（带目标 + 载荷）
    var fb: [MAX_META_LEN + 2 + 64]u8 = undefined;
    const n1 = try buildFrame(&fb, 7, STATUS_NEW, OPTION_DATA, dest, true, "hello");
    // 解析 meta
    const meta_len = std.mem.readInt(u16, fb[0..2], .big);
    const m = try parseMeta(fb[2..][0..meta_len]);
    try std.testing.expectEqual(@as(u16, 7), m.session_id);
    try std.testing.expectEqual(STATUS_NEW, m.status);
    try std.testing.expectEqual(OPTION_DATA, m.option);
    try std.testing.expectEqual(@as(u16, 8080), m.target.?.port);
    // 载荷
    const payload_off = 2 + meta_len;
    const plen = std.mem.readInt(u16, fb[payload_off..][0..2], .big);
    try std.testing.expectEqualStrings("hello", fb[payload_off + 2 ..][0..plen]);
    try std.testing.expectEqual(n1, payload_off + 2 + plen);

    // Keep 帧（followup → status=Keep）
    _ = try buildFrame(&fb, 7, STATUS_KEEP, OPTION_DATA, null, false, "abc");
    const ml2 = std.mem.readInt(u16, fb[0..2], .big);
    const m2 = try parseMeta(fb[2..][0..ml2]);
    try std.testing.expectEqual(STATUS_KEEP, m2.status);
    try std.testing.expect(m2.target == null);

    // End 帧（meta-only，无 dataLen 段）
    const n3 = try buildFrame(&fb, 7, STATUS_END, 0, null, false, "");
    try std.testing.expectEqual(@as(usize, 2 + 4), n3); // 2B len + 4B meta
    const ml3 = std.mem.readInt(u16, fb[0..2], .big);
    const m3 = try parseMeta(fb[2..][0..ml3]);
    try std.testing.expectEqual(STATUS_END, m3.status);
}

test "mux: metaLen 超限/status 非法 → 拒绝" {
    try std.testing.expectError(MuxError.TruncatedMeta, parseMeta(&.{ 0, 1 }));
    var b: [8]u8 = .{ 0, 1, 0x63, 0, 0, 0, 0, 0 }; // status=0x63
    try std.testing.expectError(MuxError.BadStatus, parseMeta(b[0..4]));
    // M19：UDP 目标照常解析（Xray 客户端对 UDP 走 XUDP over mux；解析层不再报错，
    // 由 serve 按会话降级，避免拖垮整条 mux）
    var u: [12]u8 = .{ 0, 1, STATUS_NEW, 0, TARGET_NETWORK_UDP, 0, 80, 0x01, 1, 2, 3, 4 };
    const mu = try parseMeta(u[0..12]);
    try std.testing.expectEqual(net.Network.udp, mu.target.?.network);
    try std.testing.expectEqual(@as(u16, 80), mu.target.?.port);
}

test "mux: Pipe 读写/半关闭语义" {
    var ctx = PipeCtx{ .pipe = Pipe.init(), .alloc = std.testing.allocator };
    defer ctx.pipe.deinit(std.testing.allocator);
    try ctx.pipe.writeAll("abcd", std.testing.allocator);
    var out: [8]u8 = undefined;
    try std.testing.expectEqual(@as(usize, 4), try ctx.pipe.read(out[0..]));
    try std.testing.expectEqualStrings("abcd", out[0..4]);
    // 写侧关闭 → 读侧 EOF
    ctx.pipe.closeWrite();
    try std.testing.expectEqual(@as(usize, 0), try ctx.pipe.read(out[0..]));
    // 读侧关闭 → 写侧报错
    try std.testing.expectError(error.StreamClosed, ctx.pipe.writeAll("x", std.testing.allocator));
}

test "mux: Pipe futex 阻塞唤醒（写入唤醒读者 / closeWrite 唤醒 / 多读者不丢唤醒）" {
    // M21：Pipe 从 1ms 轮询改为 futex 等待，必须验证「睡着的读者被写入/关闭唤醒」。
    const Ctx = struct {
        fn readerMain(pipe: *Pipe, out_buf: []u8, got: *std.atomic.Value(u32)) void {
            const n = pipe.read(out_buf) catch 0;
            got.store(@intCast(n), .release);
        }
    };

    // 1) 读者先睡，写入后必须被唤醒拿到数据
    {
        var pipe = Pipe.init();
        defer pipe.deinit(std.testing.allocator);
        var rbuf: [16]u8 = undefined;
        var got = std.atomic.Value(u32).init(0xFFFF_FFFF);
        const th = try std.Thread.spawn(.{ .stack_size = sys.crypto_thread_stack }, Ctx.readerMain, .{ &pipe, rbuf[0..], &got });
        sys.sleepMs(50); // 确保读者已进入 FUTEX_WAIT
        try pipe.writeAll("hello", std.testing.allocator);
        th.join();
        try std.testing.expectEqual(@as(u32, 5), got.load(.acquire));
        try std.testing.expectEqualStrings("hello", rbuf[0..5]);
    }

    // 2) 读者先睡，closeWrite 必须唤醒并返回 EOF（0）
    {
        var pipe = Pipe.init();
        defer pipe.deinit(std.testing.allocator);
        var rbuf: [16]u8 = undefined;
        var got = std.atomic.Value(u32).init(0xFFFF_FFFF);
        const th = try std.Thread.spawn(.{ .stack_size = sys.crypto_thread_stack }, Ctx.readerMain, .{ &pipe, rbuf[0..], &got });
        sys.sleepMs(50);
        pipe.closeWrite();
        th.join();
        try std.testing.expectEqual(@as(u32, 0), got.load(.acquire));
    }

    // 3) 8 读者并发 + 8 次写入：每次写入恰好唤醒一个拿到数据的读者，无丢唤醒/无永久睡死
    {
        var pipe = Pipe.init();
        defer pipe.deinit(std.testing.allocator);
        const N = 8;
        var bufs: [N][8]u8 = undefined;
        var gots: [N]std.atomic.Value(u32) = undefined;
        var ths: [N]std.Thread = undefined;
        for (0..N) |i| {
            gots[i] = std.atomic.Value(u32).init(0xFFFF_FFFF);
            // ⚠️ 每个读者只给 1 字节缓冲：read 会取 min(out.len, 可用数据)，
            // 若给 8 字节缓冲，一个读者可能一次取走全部 8 字节，其余 7 个读者永等 → 测试卡死。
            ths[i] = try std.Thread.spawn(.{ .stack_size = sys.crypto_thread_stack }, Ctx.readerMain, .{ &pipe, bufs[i][0..1], &gots[i] });
        }
        sys.sleepMs(80);
        for (0..N) |i| {
            var one: [1]u8 = .{@intCast('a' + i)};
            try pipe.writeAll(one[0..], std.testing.allocator);
        }
        for (ths) |t| t.join();
        var total: u32 = 0;
        for (0..N) |i| total += gots[i].load(.acquire);
        try std.testing.expectEqual(@as(u32, N), total); // 8 次写入被 8 个读者各取 1 字节
    }
}

test "mux: 端到端（New→上行→echo→下行→End）" {
    const testecho = @import("../testing/echo.zig");
    const freedom_mod = @import("../proxy/freedom.zig");
    const conf_freedom = @import("../conf/freedom.zig");

    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var lg = applog.Logger{ .enabled = false };
    var pool = buf.Pool.init(std.testing.allocator);
    defer pool.deinit();

    const echo = try testecho.EchoServer.start();
    defer echo.stop();

    const allow = conf_freedom.FinalRule{ .action = "allow" };
    const built = try allow.build(arena);
    var fh = freedom_mod.Handler{ .logger = &lg, .pool = &pool, .rules = &.{built} };
    const handlers = [_]dispatcher_mod.OutboundHandler{.{ .tag = "direct", .protocol = "freedom", .freedom = &fh }};
    var dsp = dispatcher_mod.Dispatcher{ .logger = &lg, .outbounds = .{ .handlers = handlers[0..] } };

    var pair = try testecho.socketpairClient(arena);
    defer pair.deinit();
    const srv_link = pair.link(); // 服务端侧（mux 链路）

    var sess = buf.Session{ .inbound_tag = "mux-test", .inbound_protocol = "vless" };
    sess.setSource("127.0.0.1:40000");

    const dest = net.Destination{ .network = .tcp, .address = .{ .ipv4 = .{ 127, 0, 0, 1 } }, .port = echo.port() };

    // 服务端 mux 主循环（线程）：读客户端帧、写出站结果
    // 用可 join 的线程：测试结束前必须确认 serve 已退出，否则 arena 先释放会 UAF
    var done = std.atomic.Value(bool).init(false);
    const th = try std.Thread.spawn(.{ .stack_size = sys.crypto_thread_stack }, serveTestWrap, .{
        arena, std.heap.smp_allocator, &dsp, &sess, srv_link, &lg, "127.0.0.1:40001", &done,
    });

    // ---- 客户端：发 New 帧（带 OptionData 载荷）----
    var fb: [MAX_META_LEN + 2 + 64]u8 = undefined;
    const n1 = try buildFrame(&fb, 1, STATUS_NEW, OPTION_DATA, dest, true, "mux-ping");
    try pair.test_side.writeAll(fb[0..n1]);

    // ---- 客户端：读回下行帧 ----
    // 首个下行帧应是 New + OptionData + "mux-ping"
    var len_b: [2]u8 = undefined;
    try readExact(&pair.test_side, &len_b);
    const dmeta_len = std.mem.readInt(u16, len_b[0..2], .big);
    var dmeta: [MAX_META_LEN]u8 = undefined;
    try readExact(&pair.test_side, dmeta[0..dmeta_len]);
    const dm = try parseMeta(dmeta[0..dmeta_len]);
    try std.testing.expectEqual(@as(u16, 1), dm.session_id);
    try std.testing.expectEqual(STATUS_KEEP, dm.status); // 响应首帧恒 Keep（NewResponseWriter followup=true）
    var plen_b: [2]u8 = undefined;
    try readExact(&pair.test_side, &plen_b);
    const plen = std.mem.readInt(u16, plen_b[0..2], .big);
    var payload: [64]u8 = undefined;
    try readExact(&pair.test_side, payload[0..plen]);
    try std.testing.expectEqualStrings("mux-ping", payload[0..plen]);

    // ---- 结束：客户端直接关 socket（真实客户端的行为）----
    // 不发 End 帧——echo 是长连接，服务端下行不会自行结束；
    // serve 主循环读到 EOF 即退出（readFull → StreamClosed → return）。
    pair.test_side.close();

    // 等 serve 真正退出再销毁 arena（最多 3s）
    var waited: u32 = 0;
    while (!done.load(.acquire) and waited < 3000) : (waited += 10) sys.sleepMs(10);
    th.join();
    try std.testing.expect(done.load(.acquire));
}

/// serve 的包装：退出时置 done（仅供测试 join）
fn serveTestWrap(
    arena: std.mem.Allocator,
    alloc: std.mem.Allocator,
    dsp: *dispatcher_mod.Dispatcher,
    sess: *const buf.Session,
    link: stream_mod.Link,
    logger: *applog.Logger,
    source: []const u8,
    done: *std.atomic.Value(bool),
) void {
    serve(arena, alloc, dsp, sess, link, logger, source);
    done.store(true, .release);
}

test "mux: End 帧 → 会话上行 EOF（出站拷贝线程应读完即退）" {
    const testecho = @import("../testing/echo.zig");
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var lg = applog.Logger{ .enabled = false };

    var pair = try testecho.socketpairClient(arena);
    defer pair.deinit();
    const srv_link = pair.link();

    // 不配出站：New 帧到达时 dispatch 会失败，但 END 分支不依赖 dispatch。
    var dsp = dispatcher_mod.Dispatcher{ .logger = &lg, .outbounds = .{ .handlers = &.{} } };
    var sess = buf.Session{ .inbound_tag = "mux-end", .inbound_protocol = "vless" };
    sess.setSource("127.0.0.1:40001");

    var done = std.atomic.Value(bool).init(false);
    const th = try std.Thread.spawn(.{ .stack_size = sys.crypto_thread_stack }, serveTestWrap, .{
        arena, std.heap.smp_allocator, &dsp, &sess, srv_link, &lg, "127.0.0.1:40001", &done,
    });

    var fb: [MAX_META_LEN + 2]u8 = undefined;
    // 未知会话的 End（上游：直接忽略，不断开）
    const n = try buildFrame(&fb, 9, STATUS_END, 0, null, false, "");
    try pair.test_side.writeAll(fb[0..n]);
    // KeepAlive 空帧（应被忽略，不断开）
    const n2 = try buildFrame(&fb, 0, STATUS_KEEP_ALIVE, 0, null, false, "");
    try pair.test_side.writeAll(fb[0..n2]);
    sys.sleepMs(100);

    // 关闭客户端 → 主循环读返回 EOF → serve 退出
    pair.test_side.close();
    var waited: u32 = 0;
    while (!done.load(.acquire) and waited < 3000) : (waited += 10) sys.sleepMs(10);
    th.join();
    try std.testing.expect(done.load(.acquire));
}

fn readExact(conn: *const sock_mod.TcpConn, out: []u8) !void {
    var off: usize = 0;
    while (off < out.len) {
        const n = try conn.read(out[off..]);
        if (n == 0) return error.UnexpectedEof;
        off += n;
    }
}

test "mux: XUDP GlobalID 解析（New + OptionData + UDP + 8B 尾随）" {
    // 构造：[sid=7][New][OptionData][UDP][port=53][ipv4=8.8.8.8][GlobalID 8B]
    var b: [20]u8 = undefined;
    std.mem.writeInt(u16, b[0..2], 7, .big);
    b[2] = STATUS_NEW;
    b[3] = OPTION_DATA;
    b[4] = TARGET_NETWORK_UDP;
    std.mem.writeInt(u16, b[5..7], 53, .big);
    b[7] = 1; // ipv4
    b[8..12].* = .{ 8, 8, 8, 8 };
    b[12..20].* = .{ 1, 2, 3, 4, 5, 6, 7, 8 };

    const m = try parseMeta(b[0..20]);
    try std.testing.expectEqual(@as(u16, 7), m.session_id);
    try std.testing.expectEqual(net.Network.udp, m.target.?.network);
    try std.testing.expectEqual(@as(u16, 53), m.target.?.port);
    try std.testing.expectEqualSlices(u8, &.{ 1, 2, 3, 4, 5, 6, 7, 8 }, &m.global_id);

    // 无 OptionData 的 New 帧不读 GlobalID（上游同样只在带首包时携带）
    b[3] = 0;
    const m2 = try parseMeta(b[0..12]); // 只给到地址结束
    try std.testing.expectEqualSlices(u8, &@as([8]u8, @splat(0)), &m2.global_id);

    // TCP 的 New 帧不读 GlobalID
    b[2] = STATUS_NEW;
    b[3] = OPTION_DATA;
    b[4] = TARGET_NETWORK_TCP;
    const m3 = try parseMeta(b[0..20]);
    try std.testing.expectEqualSlices(u8, &@as([8]u8, @splat(0)), &m3.global_id);
}
