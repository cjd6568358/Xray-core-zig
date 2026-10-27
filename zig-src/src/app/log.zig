//! 日志（上游 app/log + common/log 的服务端子集）。
//! 行格式对齐 Go log Ldate|Ltime|Lmicroseconds + 级别标签：
//!   2026/10/22 15:04:05.123456 [Warning] vless/inbound: invalid request version
//! 级别过滤在写入端做：severity ≤ 配置级别才输出（warning 档输出 Error+Warning）。
//! 错误/协议文案逐字采用上游英文原文（§5.3）。

const std = @import("std");
const sys = @import("../common/sys.zig");

pub const Severity = enum(u8) {
    err = 1,
    warning = 2,
    info = 3,
    debug = 4,

    pub fn tag(self: Severity) []const u8 {
        return switch (self) {
            .err => "[Error]",
            .warning => "[Warning]",
            .info => "[Info]",
            .debug => "[Debug]",
        };
    }
};

/// 上游 infra/conf/log.go 的级别映射：debug/info/error 识别，none 双关，
/// 其余（含 warning）一律落 Warning 档
pub const LogLevel = enum {
    debug,
    info,
    warning,
    err,
    none,

    pub fn fromString(s: []const u8) LogLevel {
        var buf: [16]u8 = undefined;
        if (s.len > buf.len) return .warning;
        for (s, 0..) |c, i| buf[i] = std.ascii.toLower(c);
        const lower = buf[0..s.len];
        if (std.mem.eql(u8, lower, "debug")) return .debug;
        if (std.mem.eql(u8, lower, "info")) return .info;
        if (std.mem.eql(u8, lower, "error")) return .err;
        if (std.mem.eql(u8, lower, "none")) return .none;
        return .warning; // warning 及其余未知值
    }

    pub fn severity(self: LogLevel) Severity {
        return switch (self) {
            .debug => .debug,
            .info => .info,
            .warning => .warning,
            .err => .err,
            .none => .warning, // none 时 logger 整体关闭，档位无意义
        };
    }
};

/// 连接打点粒度（配置键 `log.trace`，见 app/trace.zig）。
/// 独立于 loglevel：loglevel 决定"打不打得出来"，trace 决定"打多细"。
pub const TraceLevel = enum(u8) {
    off = 0,
    summary = 1,
    full = 2,

    /// 未配置 → summary（默认开，单连接一行）；未知值也落 summary
    pub fn fromString(s: []const u8) TraceLevel {
        var buf: [16]u8 = undefined;
        if (s.len > buf.len) return .summary;
        for (s, 0..) |c, i| buf[i] = std.ascii.toLower(c);
        const lower = buf[0..s.len];
        if (std.mem.eql(u8, lower, "off") or std.mem.eql(u8, lower, "none") or std.mem.eql(u8, lower, "false")) return .off;
        if (std.mem.eql(u8, lower, "full") or std.mem.eql(u8, lower, "debug")) return .full;
        return .summary;
    }
};

pub const Logger = struct {
    mu: sys.Mutex = .{},
    level: Severity = .warning,
    enabled: bool = true, // loglevel none → false
    access_fd: ?sys.Fd = null, // /dev/null 走真实打开（POSIX），"none" 为 null
    /// 连接打点粒度（app/trace.zig 读取；`Logger.init` 保持默认 summary）
    trace_level: TraceLevel = .summary,

    pub fn init(level: LogLevel, access_path: []const u8) Logger {
        var l = Logger{
            .level = level.severity(),
            .enabled = level != .none,
        };
        // access："none" → 内建关闭；否则文件分支真实打开（含 /dev/null）
        if (level != .none and access_path.len > 0 and !std.mem.eql(u8, access_path, "none")) {
            var pathz: [256]u8 = undefined;
            if (access_path.len < pathz.len) {
                @memcpy(pathz[0..access_path.len], access_path);
                pathz[access_path.len] = 0;
                const linux = std.os.linux;
                const rc = linux.open(@ptrCast(&pathz), .{ .ACCMODE = .WRONLY, .CREAT = true, .APPEND = true }, 0o644);
                if (linux.errno(rc) == .SUCCESS) {
                    l.access_fd = @intCast(rc);
                }
                // 打开失败不阻断启动（上游 access 写失败也只丢日志）
            }
        }
        return l;
    }

    pub fn deinit(self: *Logger) void {
        if (self.access_fd) |fd| sys.closeFd(fd);
        self.access_fd = null;
    }

    /// 写一条错误日志行（stderr，互斥串行化）
    pub fn log(self: *Logger, sev: Severity, msg: []const u8) void {
        if (!self.enabled) return;
        if (@intFromEnum(sev) > @intFromEnum(self.level)) return;
        self.emit(sev, msg);
    }

    /// 落盘本体（不含 loglevel 判定）：打点通道用它绕开 loglevel 门槛，
    /// 使 `log.trace` 成为真正独立的开关（loglevel=warning 时 trace 仍可出）。
    fn emit(self: *Logger, sev: Severity, msg: []const u8) void {
        if (!self.enabled) return;
        var line_buf: [1536]u8 = undefined;
        var w: usize = 0;
        w += formatTimestamp(line_buf[w..]);
        const t = sev.tag();
        @memcpy(line_buf[w..][0..t.len], t);
        w += t.len;
        line_buf[w] = ' ';
        w += 1;
        const n = @min(msg.len, line_buf.len - w - 1);
        @memcpy(line_buf[w..][0..n], msg[0..n]);
        w += n;
        line_buf[w] = '\n';
        w += 1;
        self.mu.lock();
        defer self.mu.unlock();
        sys.writeStderr(line_buf[0..w]);
    }

    pub fn err(self: *Logger, msg: []const u8) void {
        self.log(.err, msg);
    }

    pub fn warning(self: *Logger, msg: []const u8) void {
        self.log(.warning, msg);
    }

    pub fn info(self: *Logger, msg: []const u8) void {
        self.log(.info, msg);
    }

    pub fn debug(self: *Logger, msg: []const u8) void {
        self.log(.debug, msg);
    }

    // ---------------- 连接打点通道（app/trace.zig） ----------------
    // 与 info/debug 的区别：只看 `trace_level` 闸门，**不看 loglevel**
    //（现场常常 loglevel=warning 压制业务日志，但仍要看每连接汇总行）。

    pub fn traceOn(self: *const Logger) bool {
        return self.enabled and self.trace_level != .off;
    }

    pub fn traceFull(self: *const Logger) bool {
        return self.enabled and self.trace_level == .full;
    }

    /// 每连接一行汇总
    pub fn traceInfo(self: *Logger, msg: []const u8) void {
        if (!self.traceOn()) return;
        self.emit(.info, msg);
    }

    /// 阶段明细（仅 trace=full）——只翻 `log.trace` 一个开关即可看时间线，
    /// 不必同时把 loglevel 调到 debug（debug 档留给协议级逐包排障）
    pub fn traceDetail(self: *Logger, msg: []const u8) void {
        if (!self.traceFull()) return;
        self.emit(.info, msg);
    }

    /// access 记录（本配置落 /dev/null；格式对齐 common/log AccessMessage 简形）
    pub fn access(self: *Logger, msg: []const u8) void {
        const fd = self.access_fd orelse return;
        var line_buf: [1536]u8 = undefined;
        var w: usize = 0;
        w += formatTimestamp(line_buf[w..]);
        line_buf[w] = ' ';
        w += 1;
        const n = @min(msg.len, line_buf.len - w - 1);
        @memcpy(line_buf[w..][0..n], msg[0..n]);
        w += n;
        line_buf[w] = '\n';
        w += 1;
        self.mu.lock();
        defer self.mu.unlock();
        const linux = std.os.linux;
        var off: usize = 0;
        while (off < w) {
            const r = linux.write(fd, line_buf[off..].ptr, w - off);
            if (linux.errno(r) != .SUCCESS or r == 0) break;
            off += r;
        }
    }
};

/// 本地时区偏移缓存（秒；东正西负）。`std.math.minInt(i32)` = 尚未解析。
/// 只解析一次：进程生命周期内时区不会变，避免每行日志都去读文件。
var tz_offset_cache = std.atomic.Value(i32).init(std.math.minInt(i32));

/// 本地时区偏移（秒，东正西负）：`TZ` 环境变量优先，其次 `/etc/TZ`，都没有则按 UTC。
/// 注：Zig 0.17 的 std 没有 `posix.getenv`，这里用 libc 的 `getenv`（构建恒带 `-lc`）。
pub fn localOffsetSecs() i32 {
    const cached = tz_offset_cache.load(.monotonic);
    if (cached != std.math.minInt(i32)) return cached;
    const off = blk: {
        if (std.c.getenv("TZ")) |p| break :blk parsePosixTz(std.mem.span(p));
        if (readEtcTzOffset()) |o| break :blk o;
        break :blk 0;
    };
    tz_offset_cache.store(off, .monotonic);
    return off;
}

/// 读 `/etc/TZ` 并直接解析成偏移。用局部缓冲：解析只发生一次，64B 栈开销可忽略，
/// 且不引入跨线程共享缓冲（多线程同时首日志时不会撕裂）。
fn readEtcTzOffset() ?i32 {
    var buf: [64]u8 = undefined;
    const linux = std.os.linux;
    const rc = linux.open("/etc/TZ", .{ .ACCMODE = .RDONLY }, 0);
    if (linux.errno(rc) != .SUCCESS) return null;
    const fd: sys.Fd = @intCast(rc);
    defer _ = linux.close(fd);
    var total: usize = 0;
    while (total < buf.len) {
        const n = linux.read(fd, buf[total..].ptr, buf.len - total);
        switch (linux.errno(n)) {
            .SUCCESS => {},
            .INTR => continue,
            else => break,
        }
        if (n == 0) break;
        total += n;
    }
    if (total == 0) return null;
    return parsePosixTz(std.mem.trim(u8, buf[0..total], " \t\r\n"));
}

/// 解析 POSIX TZ 串的**标准时**偏移，返回"本地 = UTC + 返回值"的秒数。
///
/// POSIX 的符号与直觉相反：`UTC-8` 里的 -8 是"加到本地时间得到 UTC"，
/// 故本地偏移 = +8h = 28800（这正是现役光猫 `/etc/TZ` 的取值）。
/// 只取标准时，忽略 DST 段（`EST5EDT` 仍返回 -5h；中国无夏令时，设备也只给固定偏移）。
pub fn parsePosixTz(tz: []const u8) i32 {
    var i: usize = 0;
    // 时区名：字母串，或 POSIX 扩展的 <...> 形式
    if (i < tz.len and tz[i] == '<') {
        i += 1;
        while (i < tz.len and tz[i] != '>') i += 1;
        if (i < tz.len) i += 1;
    } else {
        while (i < tz.len and std.ascii.isAlphabetic(tz[i])) i += 1;
    }
    var negative = false;
    if (i < tz.len and (tz[i] == '+' or tz[i] == '-')) {
        negative = tz[i] == '-';
        i += 1;
    }
    var h: i32 = 0;
    var m: i32 = 0;
    var s: i32 = 0;
    var field: u2 = 0;
    var digits: u8 = 0;
    while (i < tz.len) : (i += 1) {
        const c = tz[i];
        if (c >= '0' and c <= '9') {
            digits += 1;
            const v: i32 = c - '0';
            switch (field) {
                0 => h = h * 10 + v,
                1 => m = m * 10 + v,
                else => s = s * 10 + v,
            }
        } else if (c == ':' and field < 2) {
            field += 1;
        } else break;
    }
    if (digits == 0) return 0; // 只有时区名（如 TZ=UTC）→ 偏移 0
    const magnitude = h * 3600 + m * 60 + s;
    return if (negative) magnitude else -magnitude;
}

/// "2026/10/22 15:04:05.123456 "——按**本地时区**分解，与上游 Go log 的默认行为一致。
///
/// 偏移来源：`TZ` 环境变量 → `/etc/TZ` → 兜底 UTC（见 `localOffsetSecs`）。
/// 现役光猫 `/etc/TZ=UTC-8` 即本地 CST（UTC+8）：此前版本只做 UTC 分解，
/// 日志比设备本地时间慢 8 小时（2026-10-26 巡检取证：日志末行 `01:36:32.695`
/// 对应文件 mtime `09:36:32.686`），本次已修正。历史日志（该修复之前产出的）
/// 仍是 UTC 口径，复盘时需 +8h 换算。
/// 无 DST 支持：中国无夏令时，且设备 `/etc/TZ` 只给固定偏移。
pub fn formatTimestamp(buf: []u8) usize {
    const micros = sys.nowUnixMilli();
    const millis: u64 = @intCast(@mod(micros, 1000));
    const secs: i64 = @divFloor(micros, 1000) + localOffsetSecs();
    const days: i64 = @divFloor(secs, 86400);
    const rem: u64 = @intCast(@mod(secs, 86400));
    const hour: u64 = rem / 3600;
    const minute: u64 = (rem % 3600) / 60;
    const second: u64 = rem % 60;
    const civil = civilFromDays(days);

    return (std.fmt.bufPrint(buf, "{d:0>4}/{d:0>2}/{d:0>2} {d:0>2}:{d:0>2}:{d:0>2}.{d:0>3}000 ", .{
        civil.y, civil.m, civil.d, hour, minute, second, millis,
    }) catch return 0).len;
}

/// Howard Hinnant civil_from_days（1970-01-01 = day 0）
fn civilFromDays(z_in: i64) struct { y: u64, m: u64, d: u64 } {
    const z = z_in + 719468;
    const era: i64 = @divFloor(z, 146097);
    const doe: i64 = z - era * 146097; // [0, 146096]
    const yoe: i64 = @divTrunc(doe - @divTrunc(doe, 1460) + @divTrunc(doe, 36524) - @divTrunc(doe, 146096), 365); // [0, 399]
    const y: i64 = yoe + era * 400;
    const doy: i64 = doe - (365 * yoe + @divTrunc(yoe, 4) - @divTrunc(yoe, 100)); // [0, 365]
    const mp: i64 = @divTrunc(5 * doy + 2, 153); // [0, 11]
    const d: i64 = doy - @divTrunc(153 * mp + 2, 5) + 1; // [1, 31]
    const m: i64 = if (mp < 10) mp + 3 else mp - 9; // [1, 12]
    const year: i64 = y + @as(i64, if (m <= 2) 1 else 0);
    return .{ .y = @intCast(year), .m = @intCast(m), .d = @intCast(d) };
}

test "timestamp format shape" {
    var buf: [64]u8 = undefined;
    const n = formatTimestamp(buf[0..]);
    // "2026/10/22 15:04:05.123000 " = 27 chars
    try std.testing.expectEqual(@as(usize, 27), n);
    try std.testing.expectEqual(@as(u8, '/'), buf[4]);
    try std.testing.expectEqual(@as(u8, ' '), buf[10]);
    try std.testing.expectEqual(@as(u8, ':'), buf[13]);
}

test "posix TZ offset parsing（符号反转 + 时:分）" {
    // 现役光猫 /etc/TZ 的取值：UTC-8 = 本地 UTC+8
    try std.testing.expectEqual(@as(i32, 8 * 3600), parsePosixTz("UTC-8"));
    try std.testing.expectEqual(@as(i32, 8 * 3600), parsePosixTz("CST-8"));
    try std.testing.expectEqual(@as(i32, 8 * 3600), parsePosixTz("UTC-08"));
    // 无偏移
    try std.testing.expectEqual(@as(i32, 0), parsePosixTz("UTC"));
    try std.testing.expectEqual(@as(i32, 0), parsePosixTz("UTC0"));
    try std.testing.expectEqual(@as(i32, 0), parsePosixTz(""));
    // 西半球：POSIX 正号 = 本地在 UTC 之后
    try std.testing.expectEqual(@as(i32, -5 * 3600), parsePosixTz("EST5"));
    try std.testing.expectEqual(@as(i32, -5 * 3600), parsePosixTz("EST5EDT"));
    // 半小时时区与 <...> 名称形式
    try std.testing.expectEqual(@as(i32, -19800), parsePosixTz("UTC+5:30"));
    try std.testing.expectEqual(@as(i32, 12600), parsePosixTz("<+0330>-3:30"));
}

test "log level mapping (upstream infra/conf/log.go)" {
    try std.testing.expectEqual(LogLevel.debug, LogLevel.fromString("debug"));
    try std.testing.expectEqual(LogLevel.info, LogLevel.fromString("info"));
    try std.testing.expectEqual(LogLevel.err, LogLevel.fromString("error"));
    try std.testing.expectEqual(LogLevel.none, LogLevel.fromString("none"));
    try std.testing.expectEqual(LogLevel.warning, LogLevel.fromString("warning"));
    try std.testing.expectEqual(LogLevel.warning, LogLevel.fromString("unknown-value"));
    try std.testing.expectEqual(LogLevel.warning, LogLevel.fromString("DEBUG-XX"));
}

test "trace level mapping（log.trace：off/summary/full）" {
    try std.testing.expectEqual(TraceLevel.off, TraceLevel.fromString("off"));
    try std.testing.expectEqual(TraceLevel.off, TraceLevel.fromString("NONE"));
    try std.testing.expectEqual(TraceLevel.full, TraceLevel.fromString("full"));
    try std.testing.expectEqual(TraceLevel.full, TraceLevel.fromString("Debug"));
    // 未配置/未知值 → summary（默认开）
    try std.testing.expectEqual(TraceLevel.summary, TraceLevel.fromString(""));
    try std.testing.expectEqual(TraceLevel.summary, TraceLevel.fromString("summary"));
    try std.testing.expectEqual(TraceLevel.summary, TraceLevel.fromString("whatever"));

    // 闸门语义：off 全关；summary 只出汇总；full 两档都出
    var lg = Logger{ .enabled = true, .trace_level = .off };
    try std.testing.expect(!lg.traceOn() and !lg.traceFull());
    lg.trace_level = .summary;
    try std.testing.expect(lg.traceOn() and !lg.traceFull());
    lg.trace_level = .full;
    try std.testing.expect(lg.traceOn() and lg.traceFull());
    lg.enabled = false; // loglevel none
    try std.testing.expect(!lg.traceOn() and !lg.traceFull());
}
