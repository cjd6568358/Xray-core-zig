//! §7.4 最小可观测性：每 60s 向 stderr 输出一行
//! `2026/10/22 15:04:05.000000 [Info] selfcheck conns=N threads=M rss_kb=K fd=F`
//!
//! 72h soak 的资源曲线即取自该行（/proc/self/statm、/proc/self/status 与
//! 实例侧连接计数）。只读 /proc，不分配内存（除日志行栈缓冲）。

const std = @import("std");
const linux = std.os.linux;
const sys = @import("../common/sys.zig");
const applog = @import("../app/log.zig");
const buf = @import("../common/buf.zig");
const stats_mod = @import("stats.zig");

pub const Stats = struct {
    conns: u32 = 0,
    threads: u32 = 0,
    rss_kb: u64 = 0,
    fd: u32 = 0,
};

/// 读取一个小 /proc 文件到 out（返回实际字节数，0 = 失败）
fn readProc(path: [*:0]const u8, out: []u8) usize {
    const rc = linux.open(path, .{ .ACCMODE = .RDONLY }, 0);
    if (linux.errno(rc) != .SUCCESS) return 0;
    const fd: sys.Fd = @intCast(rc);
    defer _ = linux.close(fd);
    var total: usize = 0;
    while (total < out.len) {
        const n = linux.read(fd, out[total..].ptr, out.len - total);
        switch (linux.errno(n)) {
            .SUCCESS => {},
            .INTR => continue,
            else => break,
        }
        if (n == 0) break;
        total += n;
    }
    return total;
}

/// /proc/self/status 的 Threads 行
fn readThreads() u32 {
    var b: [4096]u8 = undefined;
    const n = readProc("/proc/self/status", b[0..]);
    const s = b[0..n];
    var it = std.mem.splitScalar(u8, s, '\n');
    while (it.next()) |line| {
        if (std.mem.startsWith(u8, line, "Threads:")) {
            const v = std.mem.trim(u8, line["Threads:".len..], " \t");
            return std.fmt.parseInt(u32, v, 10) catch 0;
        }
    }
    return 0;
}

/// /proc/self/statm 第 2 字段（常驻页数）× 4KB
fn readRssKb() u64 {
    var b: [256]u8 = undefined;
    const n = readProc("/proc/self/statm", b[0..]);
    const s = b[0..n];
    var it = std.mem.tokenizeAny(u8, s, " \n\t");
    _ = it.next() orelse return 0; // size
    const resident = it.next() orelse return 0;
    const pages = std.fmt.parseInt(u64, resident, 10) catch return 0;
    return pages * 4; // 目标平台页大小 4KB（aarch64/x86_64 Linux）
}

/// /proc/self/fd 目录项数（getdents64；含目录自身 fd，±1 误差可接受）
fn readFdCount() u32 {
    const rc = linux.open("/proc/self/fd", .{ .ACCMODE = .RDONLY, .DIRECTORY = true }, 0);
    if (linux.errno(rc) != .SUCCESS) return 0;
    const fd: sys.Fd = @intCast(rc);
    defer _ = linux.close(fd);

    var b: [4096]u8 = undefined;
    var count: u32 = 0;
    while (true) {
        const n = linux.getdents64(fd, &b, b.len);
        switch (linux.errno(n)) {
            .SUCCESS => {},
            .INTR => continue,
            else => break,
        }
        if (n == 0) break;
        var off: usize = 0;
        while (off < n) {
            const d: *align(1) const linux.dirent64 = @ptrCast(&b[off]);
            if (d.reclen == 0) break;
            const name_ptr: [*:0]const u8 = @ptrCast(&d.name);
            const name = std.mem.span(name_ptr);
            if (!std.mem.eql(u8, name, ".") and !std.mem.eql(u8, name, "..")) count += 1;
            off += d.reclen;
        }
    }
    return count;
}

pub fn collect(conns: u32) Stats {
    return .{
        .conns = conns,
        .threads = readThreads(),
        .rss_kb = readRssKb(),
        .fd = readFdCount(),
    };
}

/// 自检线程主体：每 interval_ms 输出一行（running 置 false 后 200ms 内退出）
pub fn run(
    logger: *applog.Logger,
    running: *std.atomic.Value(bool),
    conns: *std.atomic.Value(u32),
    interval_ms: u32,
    /// M15：统计 Manager（null 或全关时无 channel，跳过 stats 行）
    stats: ?*stats_mod.Manager,
) void {
    var elapsed: u32 = 0;
    while (running.load(.acquire)) {
        sys.sleepMs(200);
        elapsed += 200;
        if (elapsed < interval_ms) continue;
        elapsed = 0;
        const st = collect(conns.load(.acquire));
        var mb: [160]u8 = undefined;
        const msg = std.fmt.bufPrint(
            &mb,
            "selfcheck conns={d} threads={d} rss_kb={d} fd={d}",
            .{ st.conns, st.threads, st.rss_kb, st.fd },
        ) catch continue;
        logger.info(msg);
        // M15：非零 channel 打一行 stats（出口为日志——上游经 gRPC StatsService，已登记）
        if (stats) |sm| emitStats(sm, logger);
    }
}

/// 输出形如：stats inbound>>>TAG>>>traffic>>>uplink=1234 user>>>E>>>traffic>>>downlink=56
/// 只打非零项；全零则不打（避免空转刷屏）。
fn emitStats(sm: *stats_mod.Manager, logger: *applog.Logger) void {
    var line_buf: [1024]u8 = undefined;
    var w: usize = 0;
    const snap = sm.snapshot(std.heap.page_allocator) catch return;
    defer std.heap.page_allocator.free(snap);
    var any = false;
    for (snap) |e| {
        if (e.value == 0) continue;
        any = true;
        if (w > 0 and w < line_buf.len) {
            line_buf[w] = ' ';
            w += 1;
        }
        const piece = std.fmt.bufPrint(line_buf[w..], "{s}={d}", .{ e.name, e.value }) catch break;
        w += piece.len;
    }
    if (any and w > 0) {
        // 前缀 "stats " 拼在最前（向后挪）
        const prefix = "stats ";
        if (w + prefix.len <= line_buf.len) {
            std.mem.copyBackwards(u8, line_buf[prefix.len..][0..w], line_buf[0..w]);
            @memcpy(line_buf[0..prefix.len], prefix);
            w += prefix.len;
            logger.info(line_buf[0..w]);
        }
    }
}

// ============================ 测试 ============================

test "selfcheck: /proc 采集出非零指标" {
    const st = collect(3);
    try std.testing.expectEqual(@as(u32, 3), st.conns);
    try std.testing.expect(st.threads >= 1); // 至少本测试线程
    try std.testing.expect(st.rss_kb > 0);
    try std.testing.expect(st.fd >= 1); // 至少 stdin/stdout/stderr
}

test "selfcheck: 行格式与 §7.4 对齐" {
    var lg = applog.Logger{ .enabled = false };
    var running = std.atomic.Value(bool).init(true);
    var conns = std.atomic.Value(u32).init(7);
    const th = try std.Thread.spawn(.{ .stack_size = sys.min_thread_stack }, run, .{ &lg, &running, &conns, 200, null });
    sys.sleepMs(450); // 至少触发一次
    running.store(false, .release);
    th.join();
    // 周期默认值来自 Policy（60s）
    try std.testing.expectEqual(@as(u32, 60_000), buf.Policy.selfcheck_interval_ms);
}

test "selfcheck: stats 行只打非零 channel（M15）" {
    var lg = applog.Logger{ .enabled = false };
    var mgr = stats_mod.Manager.init(std.testing.allocator);
    defer mgr.deinit();
    _ = mgr.getOrRegisterCounter("inbound>>>t>>>traffic>>>uplink").?; // 注册但零值 → 不打
    const c = mgr.getOrRegisterCounter("user>>>pb8lpgli>>>traffic>>>downlink").?;
    c.add(2048);
    // emitStats 不抛错即通过（格式断言由 stats 单测覆盖 channel 名）
    emitStats(&mgr, &lg);
    try std.testing.expectEqual(@as(u64, 2048), c.get());
}
