//! mKCP 连接核心（§5.10 表 5-6 常量与状态机；逐行对照 transport/internet/kcp/
//! connection.go + sending.go + receiving.go + config.go @ v26.10.21）。
//!
//! 线程模型（§3.1）：每会话 1 个更新线程 = Go dataUpdater（有工作按 Tti 节拍
//! flush）+ pingUpdater（空闲按 5s/终止态 1s 节拍推进状态机）合并；写/读线程经
//! futex Wakeup 唤醒更新线程。
//!
//! 生命周期（对照 Go GC 语义的显式化）：
//!   setState(.terminated) → 派生一次性清理线程（Go: go c.Terminate）——
//!   closer.close()（= listener.Remove：表移除 + 入收割队列）+ 释放窗口内存；
//!   会话线程观察到 terminated 后置 thread_done 退出；listener 收割线程对
//!   (thread_done && cleanup_done) 的会话 join + destroy。
//! 必须照抄：30s 无入包 Close；Terminating 发 Terminate 8s 强制 Terminated；
//! 对端 Terminating 4s 升级；ReadyToClose 15s 升级；RTO RFC6298（srtt=(7srtt+rtt)/8、
//! var=(3var+δ)/4、minRtt<4var → rto=srtt+4var 否则 srtt+var、上限 10000ms、
//! ×5/4、初值 100、minRtt=Tti）；ACK 延迟 max(rto/2, 20ms)；AckSegment 序号上限
//! min((mss-17)/4, 128)；窗口外序号丢弃；fast resend rto/3 折扣。

const std = @import("std");
const linux = std.os.linux;
const sys = @import("../../common/sys.zig");
const segment = @import("segment.zig");
const stream_mod = @import("../../core/stream.zig");

pub const State = enum(i32) {
    active = 0,
    ready_to_close = 1, // 本端已关
    peer_closed = 2, // 对端已关
    terminating = 3, // 本端销毁中
    peer_terminating = 4, // 对端销毁中
    terminated = 5, // 已销毁
};

pub const Config = struct {
    mtu: u32,
    tti: u32,
    cwnd_multiplier: u32,
    /// GetSendingInFlightSize（conf 层已派生，下限 8）
    sending_in_flight: u32,
    /// GetReceivingInFlightSize
    receiving_in_flight: u32,
    /// GetSendingBufferSize = maxSendingWindow/Mtu（段数）
    sending_buffer_size: u32,

    pub fn mss(self: Config) u32 {
        return self.mtu - @as(u32, segment.data_segment_overhead);
    }
};

// ============================ 基础件 ============================


fn nowMillisec() i64 {
    return sys.nowUnixMilli(); // Go now.Unix()*1000 + Nanosec/1e6
}

/// RFC6298（connection.go RoundTripInfo 逐行照抄）
pub const RoundTripInfo = struct {
    mu: sys.Mutex = .{},
    variation: u32 = 0,
    srtt: u32 = 0,
    rto: u32 = 100,
    min_rtt: u32,
    updated_timestamp: u32 = 0,

    pub fn updatePeerRTO(self: *RoundTripInfo, rto: u32, current: u32) void {
        self.mu.lock();
        defer self.mu.unlock();
        if (current -% self.updated_timestamp < 3000) return;
        self.updated_timestamp = current;
        self.rto = rto;
    }

    pub fn update(self: *RoundTripInfo, rtt: u32, current: u32) void {
        if (rtt > 0x7FFFFFFF) return;
        self.mu.lock();
        defer self.mu.unlock();
        if (self.srtt == 0) {
            self.srtt = rtt;
            self.variation = rtt / 2;
        } else {
            var delta = rtt -% self.srtt;
            if (self.srtt > rtt) delta = self.srtt - rtt;
            self.variation = (3 *% self.variation +% delta) / 4;
            self.srtt = (7 *% self.srtt +% rtt) / 8;
            if (self.srtt < self.min_rtt) self.srtt = self.min_rtt;
        }
        const rto: u32 = if (self.min_rtt < 4 *% self.variation)
            self.srtt +% 4 *% self.variation
        else
            self.srtt +% self.variation;
        const capped = if (rto > 10000) @as(u32, 10000) else rto;
        self.rto = capped * 5 / 4;
        self.updated_timestamp = current;
    }

    pub fn timeout(self: *RoundTripInfo) u32 {
        self.mu.lock();
        defer self.mu.unlock();
        return self.rto;
    }
};

/// futex 唤醒门（替代 Go signal.Notifier / Updater.WakeUp）
pub const Wakeup = struct {
    seq: std.atomic.Value(u32) = .init(0),

    pub fn signal(self: *Wakeup) void {
        _ = self.seq.fetchAdd(1, .acq_rel);
        _ = linux.futex(&self.seq.raw, .{ .cmd = .WAKE, .private = false }, 1, .{ .val2 = 0 }, null, 0);
    }

    pub fn waitTimeout(self: *Wakeup, timeout_ms: u32) void {
        const cur = self.seq.load(.acquire);
        const ts: linux.timespec = .{
            .sec = @intCast(timeout_ms / 1000),
            .nsec = @intCast((timeout_ms % 1000) * 1_000_000),
        };
        _ = linux.futex(&self.seq.raw, .{ .cmd = .WAIT, .private = false }, cur, .{ .timeout = &ts }, null, 0);
    }
};

/// 输出面：序列化 + 底层 UDP 写（RetryableWriter 语义由实现方内含）
pub const Output = struct {
    ctx: *anyopaque,
    writeFn: *const fn (ctx: *anyopaque, seg: segment.Segment) anyerror!void,

    pub fn write(self: Output, seg: segment.Segment) anyerror!void {
        return self.writeFn(self.ctx, seg);
    }
};

pub const Closer = struct {
    ctx: *anyopaque,
    closeFn: *const fn (ctx: *anyopaque) void,

    pub fn close(self: Closer) void {
        self.closeFn(self.ctx);
    }
};

// ============================ 发送侧（sending.go） ============================

const SendingWorker = struct {
    mu: sys.Mutex = .{},
    conn: *Connection,
    window: std.ArrayList(*segment.DataSegment) = .empty, // 序号递增
    first_unacknowledged: u32 = 0,
    next_number: u32 = 0,
    remote_next_number: u32 = 32,
    control_window: u32 = 0,
    fast_resend: u32 = 2,
    window_size: u32 = 0,
    retransmits: u32 = 0, // M28：重传计数（复盘用——弱网下 >0 即丢包证据）
    first_unacknowledged_updated: bool = false,
    closed: bool = false,
    total_in_flight_size: u32 = 0, // Go 在 SendingWindow；语义等价

    fn init(conn: *Connection) SendingWorker {
        return .{
            .conn = conn,
            .control_window = conn.config.sending_in_flight,
            .window_size = conn.config.sending_buffer_size,
        };
    }

    fn release(self: *SendingWorker) void {
        self.mu.lock();
        defer self.mu.unlock();
        for (self.window.items) |seg| {
            self.conn.alloc.free(seg.payload);
            self.conn.alloc.destroy(seg);
        }
        self.window.deinit(self.conn.alloc);
        self.window = .empty;
        self.closed = true;
    }

    /// Go Push：入窗（窗口持有 payload 拷贝）；窗口满/已关 → false
    fn push(self: *SendingWorker, payload: []const u8) !bool {
        self.mu.lock();
        defer self.mu.unlock();
        if (self.closed) return false;
        if (self.window.items.len > self.window_size) return false;
        const seg = self.conn.alloc.create(segment.DataSegment) catch return error.OutOfMemory;
        seg.* = .{ .number = self.next_number };
        seg.payload = self.conn.alloc.dupe(u8, payload) catch {
            self.conn.alloc.destroy(seg);
            return error.OutOfMemory;
        };
        self.window.append(self.conn.alloc, seg) catch {
            self.conn.alloc.free(seg.payload);
            self.conn.alloc.destroy(seg);
            return error.OutOfMemory;
        };
        self.next_number += 1;
        return true;
    }

    fn firstNumber(self: *SendingWorker) u32 {
        return self.window.items[0].number;
    }

    fn clear(self: *SendingWorker, una: u32) void {
        while (self.window.items.len > 0) {
            const seg = self.window.items[0];
            if (seg.number >= una) break;
            if (self.total_in_flight_size > 0) self.total_in_flight_size -= 1;
            self.conn.alloc.free(seg.payload);
            self.conn.alloc.destroy(seg);
            _ = self.window.orderedRemove(0);
        }
    }

    fn handleFastAck(self: *SendingWorker, number: u32, rto: u32) void {
        if (self.window.items.len == 0) return;
        for (self.window.items) |seg| {
            if (number == seg.number or number -% seg.number > 0x7FFFFFFF) break;
            if (seg.transmit > 0 and seg.timeout > rto / 3) {
                seg.timeout -= rto / 3;
            }
        }
    }

    fn processReceivingNext(self: *SendingWorker, next_number: u32) void {
        self.mu.lock();
        defer self.mu.unlock();
        self.clear(next_number);
        self.findFirstUnacknowledged();
    }

    fn findFirstUnacknowledged(self: *SendingWorker) void {
        const first = self.first_unacknowledged;
        if (self.window.items.len > 0) {
            self.first_unacknowledged = self.firstNumber();
        } else {
            self.first_unacknowledged = self.next_number;
        }
        if (first != self.first_unacknowledged) self.first_unacknowledged_updated = true;
    }

    fn processAck(self: *SendingWorker, number: u32) bool {
        if (number -% self.first_unacknowledged > 0x7FFFFFFF or number -% self.next_number < 0x7FFFFFFF) {
            return false;
        }
        var removed = false;
        for (self.window.items, 0..) |seg, i| {
            if (seg.number > number) break;
            if (seg.number == number) {
                if (self.total_in_flight_size > 0) self.total_in_flight_size -= 1;
                self.conn.alloc.free(seg.payload);
                self.conn.alloc.destroy(seg);
                _ = self.window.orderedRemove(i);
                removed = true;
                break;
            }
        }
        if (removed) self.findFirstUnacknowledged();
        return removed;
    }

    fn processSegment(self: *SendingWorker, current: u32, ack: *const segment.AckSegment, rto: u32) void {
        self.mu.lock();
        defer self.mu.unlock();
        if (self.closed) return;

        if (self.remote_next_number < ack.receiving_window) {
            self.remote_next_number = ack.receiving_window;
        }
        self.clear(ack.receiving_next);
        self.findFirstUnacknowledged();

        if (ack.isEmpty()) return;

        var maxack: u32 = 0;
        var maxack_removed = false;
        for (ack.numbers[0..ack.count]) |number| {
            const removed = self.processAck(number);
            if (maxack < number) {
                maxack = number;
                maxack_removed = removed;
            }
        }
        if (maxack_removed) {
            self.handleFastAck(maxack, rto);
            if (current -% ack.timestamp < 10000) {
                self.conn.round_trip.update(current -% ack.timestamp, current);
            }
        }
    }

    /// SendingWorker.Write：补 conv/SendingNext/Option 后走 output
    fn writeSeg(self: *SendingWorker, seg: *segment.DataSegment) anyerror!void {
        // 仅由 flush 持锁调用（Go 侧 Write 无锁读 firstUnacknowledged，同语义）
        seg.conv = self.conn.conv;
        seg.sending_next = self.first_unacknowledged;
        seg.option = 0;
        if (self.conn.state() == .ready_to_close) {
            seg.option = segment.OPTION_CLOSE;
        }
        try self.conn.output.write(.{ .data = seg.* });
    }

    fn onPacketLoss(self: *SendingWorker, loss_rate: u32) void {
        if (self.conn.round_trip.timeout() == 0) return;
        if (loss_rate >= 15) {
            self.control_window = 3 * self.control_window / 4;
        }
        if (loss_rate <= 5) {
            self.control_window +%= self.control_window / 4;
        }
        if (self.control_window < 16) self.control_window = 16;
        const cwnd = self.conn.config.sending_in_flight;
        if (self.control_window > cwnd) self.control_window = cwnd;
    }

    fn flush(self: *SendingWorker, current: u32) void {
        // Go：w.Lock() ... w.Unlock() 后才 Ping（Ping 要取 sending/receiving 锁，
        // 不可重入互斥锁下持锁 Ping 会自死锁——移植时曾踩坑，勿改回 defer 解锁）
        self.mu.lock();
        if (self.closed) {
            self.mu.unlock();
            return;
        }

        var cwnd = self.conn.config.sending_in_flight;
        if (cwnd > self.remote_next_number -% self.first_unacknowledged) {
            cwnd = self.remote_next_number -% self.first_unacknowledged;
        }
        if (cwnd > self.control_window) cwnd = self.control_window;
        cwnd *= self.conn.config.cwnd_multiplier;

        if (self.window.items.len > 0) {
            var lost: u32 = 0;
            var in_flight: u32 = 0;
            const rto = self.conn.round_trip.timeout();
            for (self.window.items) |seg| {
                // 未到重传时间（u32 回绕：timeout 在未来 → 差值巨大）
                if (current -% seg.timeout >= 0x7FFFFFFF) continue;
                if (seg.transmit == 0) {
                    self.total_in_flight_size += 1;
                } else {
                    lost += 1;
                    self.retransmits += 1; // M28：重传计数
                }
                seg.timeout = current +% rto;
                seg.timestamp = current;
                seg.transmit += 1;
                self.writeSeg(seg) catch {};
                in_flight += 1;
                if (in_flight >= cwnd) break;
            }
            if (in_flight > 0 and self.total_in_flight_size != 0) {
                const rate = lost * 100 / self.total_in_flight_size;
                self.onPacketLoss(rate);
            }
            self.first_unacknowledged_updated = false;
        }

        const updated = self.first_unacknowledged_updated;
        self.first_unacknowledged_updated = false;
        self.mu.unlock(); // Go: w.Unlock()
        if (updated) {
            self.conn.ping(current, .ping);
        }
    }

    fn closeWrite(self: *SendingWorker) void {
        self.mu.lock();
        defer self.mu.unlock();
        self.clear(0xFFFFFFFF);
    }

    fn isEmpty(self: *SendingWorker) bool {
        self.mu.lock();
        defer self.mu.unlock();
        return self.window.items.len == 0;
    }

    fn updateNecessary(self: *SendingWorker) bool {
        return !self.isEmpty();
    }

    fn firstUnacknowledged(self: *SendingWorker) u32 {
        self.mu.lock();
        defer self.mu.unlock();
        return self.first_unacknowledged;
    }
};

// ============================ 接收侧（receiving.go） ============================

const AckEntry = struct {
    number: u32,
    timestamp: u32,
    next_flush: u32,
};

const AckList = struct {
    conn: *Connection,
    entries: std.ArrayList(AckEntry) = .empty,
    flush_candidates: std.ArrayList(u32) = .empty,
    dirty: bool = false,
    mss: u32,

    /// NewAckSegment((mss-17)/4)：上限 128（ackNumberLimit）
    fn limit(self: *const AckList) usize {
        var l: usize = (self.mss - 17) / 4;
        if (l == 0) l = 1;
        if (l > segment.ack_number_limit) l = segment.ack_number_limit;
        return l;
    }

    fn add(self: *AckList, number: u32, timestamp: u32) !void {
        try self.entries.append(self.conn.alloc, .{ .number = number, .timestamp = timestamp, .next_flush = 0 });
        self.dirty = true;
    }

    fn clear(self: *AckList, una: u32) void {
        var count: usize = 0;
        for (self.entries.items) |e| {
            if (e.number < una) continue;
            self.entries.items[count] = e;
            count += 1;
        }
        if (count < self.entries.items.len) {
            self.entries.shrinkRetainingCapacity(count);
            self.dirty = true;
        }
    }

    fn flush(self: *AckList, current: u32, rto: u32) void {
        self.flush_candidates.clearRetainingCapacity();
        var seg = segment.AckSegment{};
        const lim = self.limit();
        for (self.entries.items) |*e| {
            if (e.next_flush > current) {
                if (self.flush_candidates.items.len < 128) {
                    self.flush_candidates.append(self.conn.alloc, e.number) catch {};
                }
                continue;
            }
            seg.putNumber(e.number);
            seg.putTimestamp(e.timestamp);
            var t = rto / 2;
            if (t < 20) t = 20; // 延迟 ACK = max(rto/2, 20ms)
            e.next_flush = current +% t;
            if (seg.isFull(lim)) {
                self.writeSeg(&seg);
                seg = segment.AckSegment{};
                self.dirty = false;
            }
        }
        if (self.dirty or !seg.isEmpty()) {
            for (self.flush_candidates.items) |number| {
                if (seg.isFull(lim)) break;
                seg.putNumber(number);
            }
            self.writeSeg(&seg);
            self.dirty = false;
        }
    }

    /// ReceivingWorker.Write：补 conv/ReceivingNext/ReceivingWindow/Option
    fn writeSeg(self: *AckList, seg: *segment.AckSegment) void {
        seg.conv = self.conn.conv;
        seg.receiving_next = self.conn.receiving.next_number;
        seg.receiving_window = self.conn.receiving.next_number +% self.conn.config.receiving_in_flight;
        seg.option = 0;
        if (self.conn.state() == .ready_to_close) {
            seg.option = segment.OPTION_CLOSE;
        }
        self.conn.output.write(.{ .ack = seg.* }) catch {};
    }
};

const PendingBuf = struct {
    data: []u8, // 归此处所有
    pos: usize = 0,
};

const ReceivingWorker = struct {
    mu: sys.Mutex = .{},
    conn: *Connection,
    left_over: std.ArrayList(PendingBuf) = .empty,
    window: std.HashMapUnmanaged(u32, *segment.DataSegment, std.hash_map.AutoContext(u32), 80) = .empty,
    acklist: AckList,
    next_number: u32 = 0,
    window_size: u32 = 0,

    fn init(conn: *Connection) ReceivingWorker {
        return .{
            .conn = conn,
            .acklist = .{ .conn = conn, .mss = conn.mss },
            .window_size = conn.config.receiving_in_flight,
        };
    }

    /// Go Release 仅清 leftOver；窗口与 acklist 在连接销毁时释放
    fn release(self: *ReceivingWorker) void {
        self.mu.lock();
        defer self.mu.unlock();
        for (self.left_over.items) |p| self.conn.alloc.free(p.data);
        self.left_over.deinit(self.conn.alloc);
        self.left_over = .empty;
    }

    fn processSendingNext(self: *ReceivingWorker, number: u32) void {
        self.mu.lock();
        defer self.mu.unlock();
        self.acklist.clear(number);
    }

    fn processSegment(self: *ReceivingWorker, seg: *const segment.DataSegment) void {
        self.mu.lock();
        defer self.mu.unlock();
        const idx = seg.number -% self.next_number;
        if (idx >= self.window_size) return; // 窗口外序号丢弃
        self.acklist.clear(seg.sending_next);
        self.acklist.add(seg.number, seg.timestamp) catch return;

        if (self.window.get(seg.number) != null) return; // 重复段
        const copy = self.conn.alloc.dupe(u8, seg.payload) catch return;
        const stored = self.conn.alloc.create(segment.DataSegment) catch {
            self.conn.alloc.free(copy);
            return;
        };
        stored.* = .{ .number = seg.number, .payload = copy };
        self.window.put(self.conn.alloc, seg.number, stored) catch {
            self.conn.alloc.free(copy);
            self.conn.alloc.destroy(stored);
        };
    }

    /// receiving.go Read（MultiBuffer 语义）：按序取段填充 out，余量进 leftOver
    fn read(self: *ReceivingWorker, out: []u8) usize {
        var total: usize = 0;
        var li: usize = 0;
        while (li < self.left_over.items.len and total < out.len) {
            const p = &self.left_over.items[li];
            const n = @min(out.len - total, p.data.len - p.pos);
            @memcpy(out[total..][0..n], p.data[p.pos..][0..n]);
            p.pos += n;
            total += n;
            if (p.pos == p.data.len) {
                self.conn.alloc.free(p.data);
                li += 1;
            }
        }
        if (li > 0) {
            std.mem.copyForwards(PendingBuf, self.left_over.items[0 .. self.left_over.items.len - li], self.left_over.items[li..]);
            self.left_over.shrinkRetainingCapacity(self.left_over.items.len - li);
        }
        if (total == out.len) return total;

        self.mu.lock();
        defer self.mu.unlock();
        while (total < out.len) {
            const removed_kv = self.window.fetchRemove(self.next_number) orelse break;
            const seg = removed_kv.value;
            self.next_number +%= 1;
            const n = @min(out.len - total, seg.payload.len);
            @memcpy(out[total..][0..n], seg.payload[0..n]);
            total += n;
            if (n < seg.payload.len) {
                const rest = self.conn.alloc.dupe(u8, seg.payload[n..]) catch {
                    self.conn.alloc.free(seg.payload);
                    self.conn.alloc.destroy(seg);
                    break;
                };
                self.left_over.append(self.conn.alloc, .{ .data = rest }) catch {
                    self.conn.alloc.free(rest);
                };
            }
            self.conn.alloc.free(seg.payload);
            self.conn.alloc.destroy(seg);
        }
        return total;
    }

    fn isDataAvailable(self: *ReceivingWorker) bool {
        self.mu.lock();
        defer self.mu.unlock();
        return self.window.get(self.next_number) != null;
    }

    fn nextNumber(self: *ReceivingWorker) u32 {
        self.mu.lock();
        defer self.mu.unlock();
        return self.next_number;
    }

    fn flushAcks(self: *ReceivingWorker, current: u32) void {
        self.mu.lock();
        defer self.mu.unlock();
        self.acklist.flush(current, self.conn.round_trip.timeout());
    }

    fn updateNecessary(self: *ReceivingWorker) bool {
        self.mu.lock();
        defer self.mu.unlock();
        return self.acklist.entries.items.len > 0;
    }
};

// ============================ Connection ============================

pub const Connection = struct {
    alloc: std.mem.Allocator,
    conv: u16,
    config: Config,
    output: Output,
    closer: Closer,
    /// 会话对端地址（listener 建会话时回填；access 日志的 from 段）
    peer: sys.SockaddrIn = .{},

    state_v: std.atomic.Value(i32) = .init(0),
    state_begin_time: std.atomic.Value(u32) = .init(0),
    last_incoming_time: std.atomic.Value(u32) = .init(0),
    last_ping_time: std.atomic.Value(u32) = .init(0),
    since_ms: i64,

    mss: u32,
    round_trip: RoundTripInfo,

    receiving: ReceivingWorker,
    sending: SendingWorker,

    data_input: Wakeup = .{},
    data_output: Wakeup = .{},
    wake_data: Wakeup = .{},

    ping_interval_ms: std.atomic.Value(u32) = .init(5000),
    rd_ms: std.atomic.Value(i64) = .init(0), // 0 = 未设
    wd_ms: std.atomic.Value(i64) = .init(0),

    thread: ?std.Thread = null,
    thread_done: std.atomic.Value(bool) = .init(false),
    cleanup_done: std.atomic.Value(bool) = .init(false),
    terminate_flag: std.atomic.Value(bool) = .init(false),

    pub fn create(
        alloc: std.mem.Allocator,
        conv: u16,
        config: Config,
        output: Output,
        closer: Closer,
    ) !*Connection {
        const self = try alloc.create(Connection);
        self.* = .{
            .alloc = alloc,
            .conv = conv,
            .config = config,
            .output = output,
            .closer = closer,
            .since_ms = nowMillisec(),
            .mss = config.mss(),
            .round_trip = .{ .min_rtt = config.tti },
            .receiving = undefined,
            .sending = undefined,
        };
        self.receiving = ReceivingWorker.init(self);
        self.sending = SendingWorker.init(self);
        self.thread = std.Thread.spawn(.{ .stack_size = sys.min_thread_stack }, sessionLoop, .{self}) catch {
            alloc.destroy(self);
            return error.ThreadSpawnFailed;
        };
        return self;
    }

    /// 收割：会话线程已退出且清理完成 → join + 销毁。返回 true 表示已销毁。
    pub fn reap(self: *Connection) bool {
        if (!self.thread_done.load(.acquire) or !self.cleanup_done.load(.acquire)) return false;
        if (self.thread) |t| t.join();
        self.destroy();
        return true;
    }

    fn destroy(self: *Connection) void {
        // 会话线程已 join，无并发访问者
        for (self.sending.window.items) |seg| {
            self.alloc.free(seg.payload);
            self.alloc.destroy(seg);
        }
        self.sending.window.deinit(self.alloc);
        var it = self.receiving.window.valueIterator();
        while (it.next()) |seg| {
            self.alloc.free(seg.*.payload);
            self.alloc.destroy(seg.*);
        }
        self.receiving.window.deinit(self.alloc);
        for (self.receiving.left_over.items) |p| self.alloc.free(p.data);
        self.receiving.left_over.deinit(self.alloc);
        self.receiving.acklist.entries.deinit(self.alloc);
        self.receiving.acklist.flush_candidates.deinit(self.alloc);
        self.alloc.destroy(self);
    }

    pub fn elapsed(self: *Connection) u32 {
        return @truncate(@as(u64, @intCast(nowMillisec() - self.since_ms)));
    }

    pub fn state(self: *Connection) State {
        return @enumFromInt(self.state_v.load(.acquire));
    }

    // ---- 读（Stream readFn；ReadMultiBuffer 语义） ----

    pub fn read(self: *Connection, out: []u8) anyerror!usize {
        while (true) {
            const st = self.state();
            if (st == .ready_to_close or st == .terminating or st == .terminated) {
                return 0; // EOF
            }
            const n = self.receiving.read(out);
            if (n > 0) {
                self.wake_data.signal(); // dataUpdater.WakeUp
                return n;
            }
            if (self.state() == .peer_terminating) return 0; // EOF
            try self.waitForDataInput();
        }
    }

    fn waitForDataInput(self: *Connection) anyerror!void {
        const rd = self.rd_ms.load(.acquire);
        var timeout_ms: u32 = 16_000; // Go：rd 零值 → 16s
        if (rd != 0) {
            const remain = rd - sys.nowMonoMs();
            if (remain <= 0) return error.Timeout;
            timeout_ms = @intCast(@min(remain, @as(i64, std.math.maxInt(u32))));
        }
        self.data_input.waitTimeout(@min(timeout_ms, 1000)); // 1s 粒度重查状态
    }

    // ---- 写（Stream writeAllFn） ----

    pub fn write(self: *Connection, data: []const u8) anyerror!void {
        var off: usize = 0;
        var update_pending = false;
        defer if (update_pending) self.wake_data.signal();

        while (true) {
            if (self.state() != .active) return error.NotOpen;

            const n = @min(self.mss, data.len - off);
            if (n == 0) return; // 全部入窗（Go: LimitReader EOF → return nil）

            const pushed = try self.sending.push(data[off..][0..n]);
            if (!pushed) {
                try self.waitForDataOutput(); // 等 ACK 腾窗
                continue;
            }
            off += n;
            update_pending = true;
            self.wake_data.signal(); // dataUpdater.WakeUp
        }
    }

    fn waitForDataOutput(self: *Connection) anyerror!void {
        const wd = self.wd_ms.load(.acquire);
        var timeout_ms: u32 = 16_000;
        if (wd != 0) {
            const remain = wd - sys.nowMonoMs();
            if (remain <= 0) return error.Timeout;
            timeout_ms = @intCast(@min(remain, @as(i64, std.math.maxInt(u32))));
        }
        self.data_output.waitTimeout(@min(timeout_ms, 1000));
    }

    // ---- 生命周期 ----

    /// Go Close()：优雅关闭（按当前状态推进）
    pub fn closeConn(self: *Connection) void {
        self.data_input.signal();
        self.data_output.signal();
        switch (self.state()) {
            .ready_to_close, .terminating, .terminated => return,
            .active => self.setState(.ready_to_close),
            .peer_closed => self.setState(.terminating),
            .peer_terminating => self.setState(.terminated),
        }
    }

    /// 强制终结（停机路径）：跳过 8s Terminate 握手，直接进 Terminated 触发清理。
    /// 上游进程收到 SIGTERM 即刻退出，不存在优雅 KCP 关闭，故此处按"尽快收尾"实现。
    pub fn forceTerminate(self: *Connection) void {
        if (self.state() == .terminated) return;
        self.setState(.terminated);
    }

    /// 会话级发送统计（M28 复盘用）：已发数据段数 / 重传次数 / 当前 RTO(ms)。
    /// 弱网下 retrans>0 即丢包证据，retrans/sent 比值即丢包率指示；
    /// rto 反映链路劣化程度（初值 100ms，上限 10000ms）。
    /// ⚠️ 调用时机：dispatch 返回后、closeConn 之前（closeConn 后 Connection
    /// 可能被 Terminate 清理线程释放）。
    pub fn sendingStats(self: *Connection) struct { sent: u32, retrans: u32, rto_ms: u32 } {
        self.sending.mu.lock();
        defer self.sending.mu.unlock();
        return .{
            .sent = self.sending.next_number,
            .retrans = self.sending.retransmits,
            .rto_ms = self.round_trip.timeout(),
        };
    }

    fn setState(self: *Connection, st: State) void {
        const current = self.elapsed();
        self.state_v.store(@intFromEnum(st), .release);
        self.state_begin_time.store(current, .release);
        self.wake_data.signal(); // 状态变更即时唤醒更新线程（Terminating 节拍切换等）

        switch (st) {
            .ready_to_close => {}, // receivingWorker.CloseRead() 为空操作
            .peer_closed => self.sending.closeWrite(),
            .terminating => {
                self.sending.closeWrite();
                self.ping_interval_ms.store(1000, .release);
            },
            .peer_terminating => {
                self.sending.closeWrite();
                self.ping_interval_ms.store(1000, .release);
            },
            .terminated => {
                // 对齐 Go SetState(StateTerminated)：CloseRead（空操作）+ CloseWrite（清发送窗）
                self.sending.closeWrite();
                self.ping_interval_ms.store(1000, .release);
                self.data_input.signal();
                self.data_output.signal();
                self.wake_data.signal();
                // Go: go c.Terminate()（避免持 Input/监听锁时同步清理死锁）
                if (std.Thread.spawn(.{ .stack_size = sys.min_thread_stack }, terminateMain, .{self})) |t| {
                    t.detach();
                } else |_| {
                    self.terminate(); // 同步兑底
                }
            },
            else => {},
        }
    }

    fn terminateMain(self: *Connection) void {
        self.terminate();
    }

    /// Go Terminate（一次性保护）
    fn terminate(self: *Connection) void {
        if (self.terminate_flag.swap(true, .acq_rel)) return;
        self.data_input.signal();
        self.data_output.signal();
        self.closer.close(); // listener.Remove（表移除 + 入收割队列）
        self.sending.release();
        self.receiving.release();
        self.cleanup_done.store(true, .release);
    }

    fn handleOption(self: *Connection, opt: u8) void {
        if ((opt & segment.OPTION_CLOSE) == segment.OPTION_CLOSE) {
            self.onPeerClosed();
        }
    }

    fn onPeerClosed(self: *Connection) void {
        switch (self.state()) {
            .ready_to_close => self.setState(.terminating),
            .active => self.setState(.peer_closed),
            else => {},
        }
    }

    /// Input：UDP 包解析出的段（调用方保证期间 conn 引用存活；段所有权留在调用方）
    pub fn input(self: *Connection, segs: []segment.Segment) void {
        const current = self.elapsed();
        self.last_incoming_time.store(current, .release);

        for (segs) |seg| {
            if (seg.conversation() != self.conv) break;

            switch (seg) {
                .data => |*s| {
                    self.handleOption(s.option);
                    self.receiving.processSegment(s);
                    if (self.receiving.isDataAvailable()) {
                        self.data_input.signal();
                    }
                    self.wake_data.signal();
                },
                .ack => |*a| {
                    self.handleOption(a.option);
                    self.sending.processSegment(current, a, self.round_trip.timeout());
                    self.data_output.signal();
                    self.wake_data.signal();
                },
                .cmd => |*c| {
                    self.handleOption(c.option);
                    if (c.cmd == .terminate) {
                        switch (self.state()) {
                            .active, .peer_closed => self.setState(.peer_terminating),
                            .ready_to_close => self.setState(.terminating),
                            .terminating => self.setState(.terminated),
                            else => {},
                        }
                    }
                    if (c.option == segment.OPTION_CLOSE or c.cmd == .terminate) {
                        self.data_input.signal();
                        self.data_output.signal();
                    }
                    self.sending.processReceivingNext(c.receiving_next);
                    self.receiving.processSendingNext(c.sending_next);
                    self.round_trip.updatePeerRTO(c.peer_rto, current);
                },
            }
        }
    }

    fn ping(self: *Connection, current: u32, cmd: segment.Command) void {
        var seg = segment.CmdOnlySegment{
            .conv = self.conv,
            .cmd = cmd,
            .receiving_next = self.receiving.nextNumber(),
            .sending_next = self.sending.firstUnacknowledged(),
            .peer_rto = self.round_trip.timeout(),
        };
        if (self.state() == .ready_to_close) {
            seg.option = segment.OPTION_CLOSE;
        }
        self.output.write(.{ .cmd = seg }) catch {};
        self.last_ping_time.store(current, .release);
    }

    fn flush(self: *Connection) void {
        const current = self.elapsed();
        if (self.state() == .terminated) return;
        if (self.state() == .active and current -% self.last_incoming_time.load(.acquire) >= 30000) {
            self.closeConn(); // 30s 无入包
        }
        if (self.state() == .ready_to_close and self.sending.isEmpty()) {
            self.setState(.terminating);
        }
        if (self.state() == .terminating) {
            self.ping(current, .terminate);
            if (current -% self.state_begin_time.load(.acquire) > 8000) {
                self.setState(.terminated); // 8s 强制完成
            }
            return;
        }
        if (self.state() == .peer_terminating and current -% self.state_begin_time.load(.acquire) > 4000) {
            self.setState(.terminating); // 对端 Terminating 4s 升级
        }
        if (self.state() == .ready_to_close and current -% self.state_begin_time.load(.acquire) > 15000) {
            self.setState(.terminating); // ReadyToClose 15s 升级
        }
        self.receiving.flushAcks(current);
        self.sending.flush(current);
        if (current -% self.last_ping_time.load(.acquire) >= 3000) {
            self.ping(current, .ping); // 3s 一跳
        }
    }

    /// 会话更新线程（§3.1：每会话 1 个；= dataUpdater + pingUpdater 合并）
    fn sessionLoop(self: *Connection) void {
        while (true) {
            const st = self.state();
            if (st == .terminated) break;
            const has_work = st != .terminating and
                (self.sending.updateNecessary() or self.receiving.updateNecessary());
            if (has_work) {
                self.flush();
                self.wake_data.waitTimeout(self.config.tti);
            } else {
                self.flush();
                self.wake_data.waitTimeout(self.ping_interval_ms.load(.acquire));
            }
        }
        self.thread_done.store(true, .release);
    }

    // ---- Stream vtable ----

    pub fn stream(self: *Connection) stream_mod.Stream {
        return .{
            .ctx = self,
            .readFn = readImpl,
            .writeAllFn = writeAllImpl,
            .closeFn = closeImpl,
            .setTimeoutFn = setTimeoutImpl,
            .shutdownWriteFn = shutdownWriteImpl,
        };
    }

    fn readImpl(ctx: *anyopaque, out: []u8) anyerror!usize {
        const self: *Connection = @ptrCast(@alignCast(ctx));
        return self.read(out);
    }

    fn writeAllImpl(ctx: *anyopaque, data: []const u8) anyerror!void {
        const self: *Connection = @ptrCast(@alignCast(ctx));
        return self.write(data);
    }

    fn closeImpl(ctx: *anyopaque) void {
        const self: *Connection = @ptrCast(@alignCast(ctx));
        self.closeConn();
    }

    fn setTimeoutImpl(ctx: *anyopaque, ms: i64) void {
        const self: *Connection = @ptrCast(@alignCast(ctx));
        const now = sys.nowMonoMs();
        const v = if (ms < 0) 0 else now + ms;
        self.rd_ms.store(v, .release);
        self.wd_ms.store(v, .release);
    }

    fn shutdownWriteImpl(ctx: *anyopaque) void {
        const self: *Connection = @ptrCast(@alignCast(ctx));
        self.closeConn(); // KCP 无半关闭；优雅收尾
    }
};

// ============================ 测试 ============================

test "RoundTripInfo RFC6298" {
    var info = RoundTripInfo{ .min_rtt = 20 };
    info.update(100, 1000); // 首次：srtt=100 var=50 → rto=100+200=300 → ×5/4=375
    try std.testing.expectEqual(@as(u32, 100), info.srtt);
    try std.testing.expectEqual(@as(u32, 375), info.rto);
    info.update(200, 2000); // delta=100 var=(150+100)/4=62 srtt=112 rto=112+248=360→450
    try std.testing.expectEqual(@as(u32, 112), info.srtt);
    try std.testing.expectEqual(@as(u32, 450), info.rto);
}

const test_config = Config{
    .mtu = 1250,
    .tti = 20,
    .cwnd_multiplier = 1,
    .sending_in_flight = 8,
    .receiving_in_flight = 8,
    .sending_buffer_size = 512,
};

/// 内存 UDP 管道：A/B 输出互投 + 泵线程搬运（模拟 listener 分发）；
/// closer 收集"表移除"事件供测试收割断言。
const Loopback = struct {
    alloc: std.mem.Allocator,
    chan: Chan,
    out_a: OutCtx,
    out_b: OutCtx,
    conn_a: *Connection,
    conn_b: *Connection,
    removed: std.atomic.Value(u32) = .init(0),
    stop: std.atomic.Value(bool) = .init(false),
    pump_thread: ?std.Thread = null,

    const Chan = struct {
        mu: sys.Mutex = .{},
        to_b: std.ArrayList([]u8) = .empty, // A→B
        to_a: std.ArrayList([]u8) = .empty, // B→A
        alloc: std.mem.Allocator,

        fn deliver(self: *Chan, from_a: bool, data: []const u8) anyerror!void {
            self.mu.lock();
            defer self.mu.unlock();
            const copy = try self.alloc.dupe(u8, data);
            const list = if (from_a) &self.to_b else &self.to_a;
            list.append(self.alloc, copy) catch {
                self.alloc.free(copy);
                return error.OutOfMemory;
            };
        }
    };

    const OutCtx = struct {
        chan: *Chan,
        from_a: bool,

        fn write(ctx: *anyopaque, seg: segment.Segment) anyerror!void {
            const self: *OutCtx = @ptrCast(@alignCast(ctx));
            var buf: [1400]u8 = undefined;
            const n = seg.byteSize();
            seg.serialize(buf[0..n]);
            try self.chan.deliver(self.from_a, buf[0..n]);
        }
    };

    fn init(self: *Loopback, alloc: std.mem.Allocator) !void {
        // 生产路径分配器（smp）：排除 testing.allocator 多线程因素
        const a = std.heap.smp_allocator;
        self.* = .{
            .alloc = a,
            .chan = .{ .alloc = a },
            .out_a = undefined,
            .out_b = undefined,
            .conn_a = undefined,
            .conn_b = undefined,
        };
        self.out_a = .{ .chan = &self.chan, .from_a = true };
        self.out_b = .{ .chan = &self.chan, .from_a = false };
        self.conn_a = try Connection.create(alloc, 0x1111, test_config, .{ .ctx = &self.out_a, .writeFn = OutCtx.write }, .{ .ctx = self, .closeFn = closerFn });
        self.conn_b = try Connection.create(alloc, 0x1111, test_config, .{ .ctx = &self.out_b, .writeFn = OutCtx.write }, .{ .ctx = self, .closeFn = closerFn });
    }

    fn closerFn(ctx: *anyopaque) void {
        // 模拟 listener.Remove：表移除（收割由测试显式做）
        const lb: *Loopback = @ptrCast(@alignCast(ctx));
        _ = lb.removed.fetchAdd(1, .acq_rel);
    }

    fn pumpOnce(self: *Loopback, from_a: bool, target: *Connection) void {
        const list = if (from_a) &self.chan.to_b else &self.chan.to_a;
        while (true) {
            var item: ?[]u8 = null;
            self.chan.mu.lock();
            if (list.items.len > 0) {
                item = list.orderedRemove(0);
            }
            self.chan.mu.unlock();
            const data = item orelse break;

            var segs: std.ArrayList(segment.Segment) = .empty;
            defer segs.deinit(self.alloc);
            segment.readPacket(self.alloc, data, &segs) catch {};
            if (segs.items.len > 0) {
                target.input(segs.items);
            }
            for (segs.items) |s2| s2.deinit(self.alloc);
            self.alloc.free(data);
        }
    }

    fn pumpMain(self: *Loopback) void {
        while (!self.stop.load(.acquire)) {
            self.pumpOnce(true, self.conn_b);
            self.pumpOnce(false, self.conn_a);
            sys.sleepMs(2);
        }
        self.pumpOnce(true, self.conn_b);
        self.pumpOnce(false, self.conn_a);
    }

    fn deinit(self: *Loopback) void {
        self.stop.store(true, .release);
        if (self.pump_thread) |t| t.join();
        self.chan.mu.lock();
        for (self.chan.to_b.items) |d| self.alloc.free(d);
        for (self.chan.to_a.items) |d| self.alloc.free(d);
        self.chan.to_b.deinit(self.alloc);
        self.chan.to_a.deinit(self.alloc);
        self.chan.mu.unlock();
    }

    /// 收割：等待两连接线程退出并销毁（测试用，替代 listener 收割线程）
    fn reapAll(self: *Loopback) void {
        var waited: u32 = 0;
        while (waited < 5000) : (waited += 10) {
            if (self.conn_a.thread_done.load(.acquire) and self.conn_a.cleanup_done.load(.acquire) and
                self.conn_b.thread_done.load(.acquire) and self.conn_b.cleanup_done.load(.acquire)) break;
            sys.sleepMs(10);
        }
        if (self.conn_a.reap()) {
            // conn_a 已销毁
        }
        if (self.conn_b.reap()) {
            // conn_b 已销毁
        }
    }
};

test "connection loopback：双向数据 + 关闭握手 + 收割无泄漏" {
    var lb: Loopback = undefined;
    try lb.init(std.testing.allocator);
    lb.pump_thread = try std.Thread.spawn(.{ .stack_size = sys.min_thread_stack }, Loopback.pumpMain, .{&lb});

    // A → B 数据（跨多段 + ACK 往返）
    try lb.conn_a.write("hello kcp loopback");
    lb.conn_b.stream().setTimeout(5000);
    var buf: [256]u8 = undefined;
    const n1 = try lb.conn_b.read(buf[0..]);
    try std.testing.expectEqualStrings("hello kcp loopback", buf[0..n1]);

    // B → A 回程
    try lb.conn_b.write("ok back");
    lb.conn_a.stream().setTimeout(5000);
    const n2 = try lb.conn_a.read(buf[0..]);
    try std.testing.expectEqualStrings("ok back", buf[0..n2]);

    // A 优雅关闭 → 状态变更唤醒会话线程 → Terminate 立即发出 → B 读到 EOF
    lb.conn_a.closeConn();
    var waited: u32 = 0;
    while (waited < 3000) : (waited += 10) {
        const st = lb.conn_b.state();
        if (st == .peer_terminating or st == .terminating or st == .terminated) break;
        sys.sleepMs(10);
    }
    const n3 = lb.conn_b.read(buf[0..]) catch 0;
    try std.testing.expectEqual(@as(usize, 0), n3);
    try std.testing.expect(lb.conn_b.state() == .peer_terminating or
        lb.conn_b.state() == .terminating or
        lb.conn_b.state() == .terminated);

    // 强制收敛（不等 4s/8s 真实定时器）→ 收割（join + destroy，testing.allocator 查泄漏）
    lb.conn_a.setState(.terminated);
    lb.conn_b.setState(.terminated);
    lb.reapAll();
    try std.testing.expectEqual(@as(u32, 2), lb.removed.load(.acquire)); // 两端各表移除一次
    lb.deinit();
}
