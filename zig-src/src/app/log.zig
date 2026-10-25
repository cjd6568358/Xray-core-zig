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

pub const Logger = struct {
    mu: sys.Mutex = .{},
    level: Severity = .warning,
    enabled: bool = true, // loglevel none → false
    access_fd: ?sys.Fd = null, // /dev/null 走真实打开（POSIX），"none" 为 null

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

/// "2026/10/22 15:04:05.123456 "（UTC；Go log 默认本地时区，设备容器为 UTC，行为等价）
pub fn formatTimestamp(buf: []u8) usize {
    const micros = sys.nowUnixMilli();
    const secs: u64 = @intCast(@divFloor(micros, 1000));
    const millis: u64 = @intCast(@mod(micros, 1000));
    const days: u64 = secs / 86400;
    const rem: u64 = secs % 86400;
    const hour: u64 = rem / 3600;
    const minute: u64 = (rem % 3600) / 60;
    const second: u64 = rem % 60;
    const civil = civilFromDays(@intCast(days));

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

test "log level mapping (upstream infra/conf/log.go)" {
    try std.testing.expectEqual(LogLevel.debug, LogLevel.fromString("debug"));
    try std.testing.expectEqual(LogLevel.info, LogLevel.fromString("info"));
    try std.testing.expectEqual(LogLevel.err, LogLevel.fromString("error"));
    try std.testing.expectEqual(LogLevel.none, LogLevel.fromString("none"));
    try std.testing.expectEqual(LogLevel.warning, LogLevel.fromString("warning"));
    try std.testing.expectEqual(LogLevel.warning, LogLevel.fromString("unknown-value"));
    try std.testing.expectEqual(LogLevel.warning, LogLevel.fromString("DEBUG-XX"));
}
