//! xrayz — Xray-core 服务端子集的 Zig 实现（Phase 1）
//!
//! CLI 形态对齐上游 main/run.go：
//!   xrayz run [-c config.json]         启动（默认 cwd config.json）
//!   xrayz run -test [-c config.json]   仅校验配置：通过打 "Configuration OK." exit 0
//!   xrayz version                      打印版本
//! 配置错误 exit 23（对齐 main/run.go:87），启动失败 exit -1(255)。

const std = @import("std");
pub const sys = @import("common/sys.zig");

// 模块导出（tests/ 通过 @import("xrayz") 引用）
pub const kdf = @import("crypto/kdf.zig");
pub const cfb = @import("crypto/cfb.zig");
pub const chacha_key = @import("crypto/chacha_key.zig");
pub const vmess_aead = @import("proxy/vmess/aead.zig");
pub const vmess_encoding = @import("proxy/vmess/encoding.zig");
pub const vless_encoding = @import("proxy/vless/encoding.zig");
pub const uuid = @import("common/uuid.zig");
pub const net = @import("common/net.zig");
pub const addr = @import("common/addr.zig");
pub const applog = @import("app/log.zig");
pub const selfcheck = @import("app/selfcheck.zig");
pub const stats = @import("app/stats.zig");
pub const trace = @import("app/trace.zig");
pub const conf = @import("conf/config.zig");
pub const conf_transport = @import("conf/transport.zig");
pub const conf_freedom = @import("conf/freedom.zig");
pub const conf_vless = @import("conf/vless.zig");
pub const conf_vmess = @import("conf/vmess.zig");

pub const version = "0.1.0";
pub const config_error_exit_code: u8 = 23;
pub const startup_error_exit_code: u8 = 255; // Go os.Exit(-1)

// M3 运行时模块导出
pub const sock = @import("common/sock.zig");
pub const buffer = @import("common/buf.zig");
pub const core_stream = @import("core/stream.zig");
pub const core_instance = @import("core/instance.zig");
pub const dispatcher = @import("app/dispatcher.zig");
pub const freedom = @import("proxy/freedom.zig");
pub const ws_frame = @import("transport/websocket/frame.zig");
pub const ws_server = @import("transport/websocket/server.zig");
pub const vless_inbound = @import("proxy/vless/inbound.zig");
pub const kcp_segment = @import("transport/kcp/segment.zig");
pub const kcp_conn = @import("transport/kcp/conn.zig");
pub const kcp_listener = @import("transport/kcp/listener.zig");
pub const vmess_replay = @import("proxy/vmess/replay.zig");
pub const vmess_validator = @import("proxy/vmess/validator.zig");
pub const vmess_chunk = @import("proxy/vmess/chunk.zig");
pub const vmess_inbound = @import("proxy/vmess/inbound.zig");

const usage =
    \\XrayZ - Xray-core server subset in Zig (Phase 1)
    \\
    \\Usage:
    \\  {s} run [-c config.json]           run the server (default: ./config.json)
    \\  {s} run -test [-c config.json]     test config file validity
    \\  {s} version                        print version
    \\
;

pub const LoadedConfig = struct {
    path: []const u8,
    bytes: []const u8,
};

/// 读配置文件（M2 起替换为 conf 层结构化解析；此阶段仅验证可读 + JSON 合法）
pub fn loadConfigBytes(alloc: std.mem.Allocator, path: []const u8) ![]const u8 {
    const linux = std.os.linux;
    const pathz = try alloc.dupeSentinel(u8, path, 0);
    defer alloc.free(pathz);

    const rc = linux.open(pathz, .{ .ACCMODE = .RDONLY }, 0);
    switch (linux.errno(rc)) {
        .SUCCESS => {},
        .NOENT => return error.FileNotFound,
        .ACCES => return error.AccessDenied,
        else => return error.Unexpected,
    }
    const fd: sys.Fd = @intCast(rc);
    defer _ = linux.close(fd);

    var list: std.ArrayList(u8) = .empty;
    errdefer list.deinit(alloc);
    var buf: [8192]u8 = undefined;
    while (true) {
        const n = linux.read(fd, &buf, buf.len);
        switch (linux.errno(n)) {
            .SUCCESS => {},
            .INTR => continue,
            else => return error.Unexpected,
        }
        if (n == 0) break;
        try list.appendSlice(alloc, buf[0..n]);
    }
    return list.toOwnedSlice(alloc);
}

pub fn main(init: std.process.Init) !u8 {
    const arena = init.arena.allocator();
    const argv = try init.minimal.args.toSlice(arena);

    if (argv.len < 2) {
        try printUsage(argv[0]);
        return 1;
    }

    const cmd = argv[1];
    if (std.mem.eql(u8, cmd, "version")) {
        var buf: [128]u8 = undefined;
        const msg = try std.fmt.bufPrint(&buf, "XrayZ {s} (Xray-core v26.10.21 semantics)\n", .{version});
        sys.writeStderr(msg);
        return 0;
    }
    if (!std.mem.eql(u8, cmd, "run")) {
        try printUsage(argv[0]);
        return 1;
    }

    // run [-test] [-c path]
    var test_only = false;
    var config_path: []const u8 = "config.json";
    var i: usize = 2;
    while (i < argv.len) : (i += 1) {
        const a = argv[i];
        if (std.mem.eql(u8, a, "-test")) {
            test_only = true;
        } else if (std.mem.eql(u8, a, "-c") or std.mem.eql(u8, a, "-config")) {
            i += 1;
            if (i >= argv.len) {
                sys.writeStderr("missing value after -c\n");
                return 1;
            }
            config_path = argv[i];
        } else {
            var buf: [256]u8 = undefined;
            const msg = std.fmt.bufPrint(&buf, "unknown flag: {s}\n", .{a}) catch "unknown flag\n";
            sys.writeStderr(msg);
            return 1;
        }
    }

    return runCommand(arena, config_path, test_only) catch |err| switch (err) {
        error.FileNotFound => {
            var buf: [512]u8 = undefined;
            const msg = std.fmt.bufPrint(&buf, "failed to read config file: {s}\n", .{config_path}) catch "failed to read config\n";
            sys.writeStderr(msg);
            return config_error_exit_code;
        },
        else => {
            sys.writeStderr("failed to start: unexpected error\n");
            return config_error_exit_code;
        },
    };
}

fn runCommand(alloc: std.mem.Allocator, config_path: []const u8, test_only: bool) !u8 {
    const bytes = loadConfigBytes(alloc, config_path) catch |err| {
        if (test_only) {
            var buf: [512]u8 = undefined;
            const msg = std.fmt.bufPrint(&buf, "failed to read config file: {s} ({s})\n", .{ config_path, @errorName(err) }) catch "failed to read config\n";
            sys.writeStderr(msg);
            return config_error_exit_code;
        }
        return err;
    };

    var arena_state = std.heap.ArenaAllocator.init(alloc);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var logger = applog.Logger.init(applog.LogLevel.warning, ""); // 校验阶段告警先落 stderr
    defer logger.deinit();

    const root = conf.parseRoot(arena, bytes) catch {
        sys.writeStderr("failed to parse config: invalid JSON\n");
        return config_error_exit_code;
    };
    var diag = conf.Diag{};
    const runtime = conf.buildRuntime(arena, &logger, &root, &diag) catch |e| {
        var buf: [640]u8 = undefined;
        const detail = if (diag.len > 0) diag.message() else @errorName(e);
        const msg = std.fmt.bufPrint(&buf, "failed to build config: {s}\n", .{detail}) catch "failed to build config\n";
        sys.writeStderr(msg);
        return config_error_exit_code;
    };

    if (test_only) {
        sys.writeStderr("Configuration OK.\n");
        return 0;
    }

    // —— M3 起接入 core.Instance（启动失败 exit 255，对齐 main/run.go exit(-1)）——
    const gpa = std.heap.smp_allocator;
    var run_logger = applog.Logger.init(runtime.log_level, runtime.access_path);
    run_logger.trace_level = runtime.trace_level; // log.trace：连接打点粒度
    defer run_logger.deinit();

    const inst = core_instance.Instance.create(gpa, &runtime, &run_logger, version) catch {
        sys.writeStderr("failed to create core instance\n");
        return startup_error_exit_code;
    };
    core_instance.installSignalHandlers();
    inst.start() catch |e| {
        var eb: [160]u8 = undefined;
        const em = std.fmt.bufPrint(&eb, "failed to start: {s}\n", .{@errorName(e)}) catch "failed to start\n";
        sys.writeStderr(em);
        inst.stop();
        inst.destroy();
        return startup_error_exit_code;
    };

    // 主线程等信号（SIGINT/SIGTERM 置位后优雅退出）
    while (!core_instance.shutdownRequested()) sys.sleepMs(200);

    inst.stop();
    inst.destroy();
    return 0;
}

fn printUsage(prog: []const u8) !void {
    var buf: [1024]u8 = undefined;
    const msg = try std.fmt.bufPrint(&buf, usage, .{ prog, prog, prog });
    sys.writeStderr(msg);
}

test {
    _ = sys;
    // 引用各模块 decl：强制分析并收集源内单测（0.17 惰性分析不会自动收集未引用文件）
    _ = &kdf.kdf16;
    _ = &cfb.Cfb.initEncryptor;
    _ = &chacha_key.generateChacha20Poly1305Key;
    _ = &vmess_aead.sealHeader;
    _ = &vmess_encoding.encodeResponseHeader;
    _ = &vless_encoding.encodeRequestHeader;
    _ = &uuid.Uuid.parse;
    _ = &net.Address.parseAddress;
    _ = &addr.writePortThenAddress;
    _ = &applog.Logger.log;
    _ = &applog.TraceLevel.fromString;
    _ = &conf.buildRuntime;
    _ = &conf_transport.StreamConfig.build;
    _ = &conf_freedom.FreedomConfig.build;
    _ = &conf_vless.VlessInboundConfig.build;
    _ = &conf_vmess.VmessInboundConfig.build;
    _ = &loadConfigBytes;
    // M3 运行时
    _ = &sock.TcpConn.read;
    _ = &buffer.Pool.get;
    // 连接生命周期打点
    _ = &trace.Trace.init;
    _ = &trace.Trace.finish;
    _ = &trace.emitAggregate;
    _ = &core_stream.TcpStreamCtx.stream;
    _ = &dispatcher.Dispatcher.dispatch;
    _ = &freedom.Handler.process;
    _ = &core_instance.Instance.start;
    _ = &core_instance.installSignalHandlers;
    // M4 WebSocket
    _ = &ws_frame.parseBase;
    _ = &ws_server.handshake;
    _ = &ws_server.Session.stream;
    // M5 VLESS 入站
    _ = &vless_inbound.handle;
    _ = &vless_inbound.parseHeader;
    _ = &vless_inbound.PrefixedReader.stream;
    // M6 mKCP
    _ = &kcp_segment.readPacket;
    _ = &kcp_conn.Connection.create;
    _ = &kcp_listener.Listener.create;
    // M7 VMess 入站
    _ = &vmess_replay.ReplayFilter.check;
    _ = &vmess_replay.SessionHistory.addIfNotExists;
    _ = &vmess_chunk.AuthReader.read;
    _ = &vmess_chunk.AuthWriter.writeAll;
    _ = &vmess_inbound.handle;
}
