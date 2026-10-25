//! 底层系统封装：时间 / 睡眠 / stderr / sockaddr / socket 原语。
//!
//! zig 0.17 中 std.posix 的 socket 面已被移入 std.Io（vtable 化），
//! 本项目为 linux-only（x86_64 开发 + aarch64-musl 目标），网络层直接走
//! std.os.linux 的 syscall 包装——ABI 级稳定、无 Io 实例依赖、可完全控制
//! SO_RCVTIMEO/SO_REUSEPORT 等 sockopt。

const std = @import("std");
const linux = std.os.linux;

pub const E = linux.E;
pub const Fd = linux.fd_t;

/// 线程栈下限：glibc 2.41（开发机）实测 ≥384KB 才能创建，
/// musl 静态（目标设备）64KB 可用。所有 spawn 统一走 this floor。
pub const min_thread_stack: usize = if (@import("builtin").abi.isMusl()) 64 * 1024 else 512 * 1024;

/// 密码线程栈：VMess 分块体 AES-GCM（+SHAKE）调用链在**软件 AES**（无 AES-NI 的
/// x86_64 / 通用 aarch64 目标）上帧深实测 >64KB（打包机复现：64KB 段错误，
/// 128KB 通过）。凡触碰 AEAD/KDF/SHAKE 的线程（协议 handler、freedom 拷贝
/// 线程、KCP 会话线程）一律用此栈；非密码路径继续用 min_thread_stack。
/// 栈按需分页，512KB 为虚拟上限，物理占用仅触及页。
pub const crypto_thread_stack: usize = 512 * 1024;

// ============================ 时间 ============================

/// CLOCK_REALTIME 秒（VMess AuthID 时间窗、日志时间戳用）
pub fn nowUnixSecs() i64 {
    var ts: linux.timespec = undefined;
    const rc = linux.clock_gettime(.REALTIME, &ts);
    if (linux.errno(rc) != .SUCCESS) return 0;
    return @intCast(ts.sec);
}

pub fn nowUnixMilli() i64 {
    var ts: linux.timespec = undefined;
    const rc = linux.clock_gettime(.REALTIME, &ts);
    if (linux.errno(rc) != .SUCCESS) return 0;
    return @as(i64, @intCast(ts.sec)) * 1000 + @divTrunc(@as(i64, @intCast(ts.nsec)), 1_000_000);
}

/// CLOCK_MONOTONIC 毫秒（超时/空闲判定用，不受校时影响）
pub fn nowMonoMs() i64 {
    var ts: linux.timespec = undefined;
    const rc = linux.clock_gettime(.MONOTONIC, &ts);
    if (linux.errno(rc) != .SUCCESS) return 0;
    return @as(i64, @intCast(ts.sec)) * 1000 + @divTrunc(@as(i64, @intCast(ts.nsec)), 1_000_000);
}

pub fn monoNanos() i128 {
    var ts: linux.timespec = undefined;
    const rc = linux.clock_gettime(.MONOTONIC, &ts);
    if (linux.errno(rc) != .SUCCESS) return 0;
    return @as(i128, @intCast(ts.sec)) * 1_000_000_000 + @as(i128, @intCast(ts.nsec));
}

pub fn sleepMs(ms: u64) void {
    const req: linux.timespec = .{
        .sec = @intCast(ms / 1000),
        .nsec = @intCast((ms % 1000) * 1_000_000),
    };
    // 相对睡眠（TIMER.ABSTIME = false），EINTR 重试
    var remain: linux.timespec = undefined;
    while (true) {
        const rc = linux.clock_nanosleep(.MONOTONIC, .{ .ABSTIME = false }, &req, &remain);
        switch (linux.errno(rc)) {
            .SUCCESS, .INVAL => return,
            .INTR => continue,
            else => return,
        }
    }
}

// ============================ 同步原语 ============================

/// futex 阻塞互斥锁（0.17 移除了 std.Thread.Mutex；std.Io.Mutex 需 Io 实例，不用）
///
/// 算法取 musl __lock/__unlock 形态：**state 只表示"是否持有"，等待者另记计数**。
/// 早期实现用经典三态（0/1/2 表示 contended），在"唤醒 1 个"时会出现孤儿等待者：
/// 被唤醒者抢锁失败重新睡下（state=2），而抢到锁者以 state==1 解锁（swap 得 1 不触发
/// wake）→ 剩下的等待者永久睡死。M9 实机 KCP 数据面死锁即由此而来（写线程卡在
/// SendingWorker.push 的 lock 上，进程里却没有任何线程持有该锁）。
/// 现在：unlock 只要"曾有等待者（waiters>0）"就唤醒 1 个，等待者每次醒来重新 swap 抢锁，
/// 不存在丢失唤醒的窗口；等待本身另设 1s 超时上限，任何残余异常都不会变成永久挂死。
pub const Mutex = struct {
    state: std.atomic.Value(u32) = .init(0), // 0=空闲 1=已持有
    waiters: std.atomic.Value(u32) = .init(0), // 等待者计数（只增不减到抢到锁为止）

    pub fn lock(self: *Mutex) void {
        if (self.state.cmpxchgStrong(0, 1, .acquire, .monotonic) == null) return;
        self.lockSlow();
    }

    fn lockSlow(self: *Mutex) void {
        _ = self.waiters.fetchAdd(1, .monotonic);
        while (self.state.swap(1, .acquire) != 0) {
            // 期望值恒为 1（已持有）；醒来后重新 swap 抢锁
            const ts: linux.timespec = .{ .sec = 1, .nsec = 0 };
            _ = linux.futex(&self.state.raw, .{ .cmd = .WAIT, .private = false }, 1, .{ .timeout = &ts }, null, 0);
        }
        _ = self.waiters.fetchSub(1, .monotonic);
    }

    pub fn unlock(self: *Mutex) void {
        if (self.state.swap(0, .release) != 0 and self.waiters.load(.monotonic) > 0) {
            _ = linux.futex(&self.state.raw, .{ .cmd = .WAKE, .private = false }, 1, .{ .val2 = 0 }, null, 0);
        }
    }

    pub fn tryLock(self: *Mutex) bool {
        return self.state.cmpxchgStrong(0, 1, .acquire, .monotonic) == null;
    }
};

test "Mutex：高并发互斥 + 无等待者丢失（M9 回归）" {
    const Ctx = struct {
        mu: Mutex = .{},
        counter: u64 = 0,
        done: std.atomic.Value(u32) = .init(0),

        fn worker(self: *@This(), iters: u32) void {
            var i: u32 = 0;
            while (i < iters) : (i += 1) {
                self.mu.lock();
                self.counter += 1;
                self.mu.unlock();
                // 制造多等待者交错的时序
                if (i % 64 == 0) std.Thread.yield() catch {};
            }
            _ = self.done.fetchAdd(1, .acq_rel);
        }
    };

    const threads = 8;
    const iters = 20_000;
    var ctx = Ctx{};
    var hs: [threads]std.Thread = undefined;
    for (&hs) |*h| {
        h.* = try std.Thread.spawn(.{ .stack_size = min_thread_stack }, Ctx.worker, .{ &ctx, iters });
    }
    // 全部线程必须能跑完（旧实现可能永久睡死 → join 挂起，测试超时即失败）
    for (hs) |h| h.join();
    try std.testing.expectEqual(@as(u64, threads * iters), ctx.counter);
}

// ============================ 输出 ============================

pub fn writeStderr(bytes: []const u8) void {
    if (bytes.len == 0) return;
    var off: usize = 0;
    while (off < bytes.len) {
        const n = linux.write(2, bytes.ptr + off, bytes.len - off);
        const err = linux.errno(n);
        if (err == .INTR) continue;
        if (err != .SUCCESS) return;
        if (n == 0) return;
        off += n;
    }
}

pub fn exit(code: u8) noreturn {
    linux.exit(code);
}

// ============================ sockaddr ============================

/// IPv4：内存布局与内核 sockaddr_in 完全一致（16 字节）
pub const SockaddrIn = extern struct {
    family: u16 = linux.AF.INET,
    port_be: u16 = 0,
    addr: [4]u8 = .{ 0, 0, 0, 0 },
    zero: [8]u8 = [8]u8{ 0, 0, 0, 0, 0, 0, 0, 0 },

    pub fn init(octets: [4]u8, port_num: u16) SockaddrIn {
        return .{ .port_be = std.mem.nativeToBig(u16, port_num), .addr = octets };
    }

    pub fn port(sa: *const SockaddrIn) u16 {
        return std.mem.bigToNative(u16, sa.port_be);
    }

    pub fn any(port_num: u16) SockaddrIn {
        return init(.{ 0, 0, 0, 0 }, port_num);
    }
};

/// IPv6：28 字节，布局同内核 sockaddr_in6
pub const SockaddrIn6 = extern struct {
    family: u16 = linux.AF.INET6,
    port_be: u16 = 0,
    flowinfo: u32 = 0,
    addr: [16]u8 = @splat(0),
    scope_id: u32 = 0,

    pub fn init(octets: [16]u8, port_num: u16) SockaddrIn6 {
        return .{ .port_be = std.mem.nativeToBig(u16, port_num), .addr = octets };
    }

    pub fn port(sa: *const SockaddrIn6) u16 {
        return std.mem.bigToNative(u16, sa.port_be);
    }

    pub fn any(port_num: u16) SockaddrIn6 {
        return .{ .port_be = std.mem.nativeToBig(u16, port_num) };
    }
};

pub const Sockaddr = union(enum) {
    v4: SockaddrIn,
    v6: SockaddrIn6,

    pub fn port(self: Sockaddr) u16 {
        return switch (self) {
            inline else => |*sa| sa.port(),
        };
    }
};

// ============================ socket 原语 ============================

pub fn errnoOf(rc: usize) E {
    return linux.errno(rc);
}

/// 把 syscall 返回的 usize 转成 E 或截断为实际返回值（fd/字节数）
pub fn check(rc: usize, positive_max: usize) E!usize {
    const err = linux.errno(rc);
    if (err != .SUCCESS) return err;
    return @min(rc, positive_max);
}

pub fn closeFd(fd: Fd) void {
    _ = linux.close(fd);
}

// ============================ 随机数 ============================

var rng_mu: Mutex = .{};
var rng_state: ?std.Random.DefaultCsprng = null;
var rng_ready = false;

fn ensureRng() void {
    if (rng_ready) return;
    var seed: [32]u8 = @splat(0);
    var got: usize = 0;
    const fd_rc = linux.open("/dev/urandom", .{ .ACCMODE = .RDONLY }, 0);
    if (linux.errno(fd_rc) == .SUCCESS) {
        const fdi: Fd = @intCast(fd_rc);
        while (got < seed.len) {
            const n = linux.read(fdi, seed[got..].ptr, seed.len - got);
            const err = linux.errno(n);
            if (err != .SUCCESS or n == 0) break;
            got += n;
        }
        _ = linux.close(fdi);
    }
    if (got < seed.len) {
        // 退化路径：时间熵 + 地址熵。仅影响随机度，不影响协议正确性。
        var h = std.hash.Wyhash.init(0);
        const t: u64 = @bitCast(nowMonoMs());
        const u: u64 = @bitCast(nowUnixMilli());
        const stack_addr: usize = @intFromPtr(&seed);
        h.update(std.mem.asBytes(&t));
        h.update(std.mem.asBytes(&u));
        h.update(std.mem.asBytes(&stack_addr));
        h.update(std.mem.asBytes(&got));
        var i: usize = 0;
        var ctr: u64 = 0;
        while (i < seed.len) : (i += 8) {
            ctr += 1;
            h.update(std.mem.asBytes(&ctr));
            const f = h.final();
            @memcpy(seed[i .. i + 8], std.mem.asBytes(&f));
        }
    }
    rng_state = std.Random.DefaultCsprng.init(seed);
    rng_ready = true;
}

/// 业务随机（nonce/padding）：线程安全填充
pub fn randomBytes(buf: []u8) void {
    rng_mu.lock();
    defer rng_mu.unlock();
    ensureRng();
    rng_state.?.random().bytes(buf);
}

test "mutex contention" {
    var mu = Mutex{};
    mu.lock();
    mu.unlock();
    mu.lock();
    mu.unlock();
}

test {
    _ = writeStderr;
    _ = sleepMs;
}
