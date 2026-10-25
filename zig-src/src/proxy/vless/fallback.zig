//! VLESS fallbacks（对照 proxy/vless/inbound/inbound.go 302-460 行 + config.pb.go Fallback）
//!
//! 语义：VLESS 请求头解析失败且配置了 fallbacks 时**不关连接**，而是把客户端
//! （含已读首字节）转交到回落目标——抗探测。
//!
//! 选择（三级，上游 napfb[name][alpn][path]）：
//!   name（TLS/REALITY SNI）→ alpn → path（首包前 ~60B 的 HTTP 请求行 path）
//!   本实现无 TLS → name/alpn 恒空，实际按 path 选择；逐级取不到用默认（path=""）。
//! 落地：ExponentialBackoff(5,100) dial → 可选 PROXY protocol v1 头 → 先写已读首字节
//!   → 双向拷贝（空闲上限 ConnectionIdle）。
//!
//! 范围（已登记）：Xver 仅 v1（文本头）；VMess 上游无 fallbacks；WS 层 path 不匹配
//! 仍由 WS 层拒（与上游一致，不改）。

const std = @import("std");
const sys = @import("../../common/sys.zig");
const sock = @import("../../common/sock.zig");
const stream_mod = @import("../../core/stream.zig");
const conf_vless = @import("../../conf/vless.zig");
const applog = @import("../../app/log.zig");
const buf = @import("../../common/buf.zig");

const Fallback = conf_vless.Fallback;

/// 从首包提取 HTTP 请求行 path（上游 375-400 行的字节级扫描）
/// 条件：firstLen >= 18 且 first[4] != '*'（非 h2c）；在 [4,8] 找 '/' 且前字节为 ' '，
/// 随后到 '?' 或 ' ' 为止。找不到返回 ""。
pub fn extractPath(first: []const u8) []const u8 {
    if (first.len < 18) return "";
    if (first[4] == '*') return ""; // h2c 前缀不走 path 提取
    var i: usize = 4;
    while (i <= 8) : (i += 1) {
        if (first[i] == '/' and first[i - 1] == ' ') {
            var search: usize = first.len;
            if (search > 64) search = 64;
            var j: usize = i + 1;
            while (j < search) : (j += 1) {
                const k = first[j];
                if (k == '\r' or k == '\n') break;
                if (k == '?' or k == ' ') return first[i..j];
            }
            break;
        }
    }
    return "";
}

/// 选择回落项（上游三级 map 的扁平等价；无 TLS → name/alpn 恒空）
pub fn selectFallback(fallbacks: []const Fallback, first: []const u8) ?*const Fallback {
    if (fallbacks.len == 0) return null;
    const path = extractPath(first);
    // 1) path 精确匹配（name="" alpn=""）
    for (fallbacks) |*fb| {
        if (fb.name.len == 0 and fb.alpn.len == 0 and std.mem.eql(u8, fb.path, path)) return fb;
    }
    // 2) 默认项（path=""）
    for (fallbacks) |*fb| {
        if (fb.name.len == 0 and fb.alpn.len == 0 and fb.path.len == 0) return fb;
    }
    return null; // 上游：`failed to find the default "path" config` → 关连接
}

/// PROXY protocol v1 文本头（上游 434-470 的 xver==1 分支）
/// `PROXY TCP4 <remoteAddr> <localAddr> <remotePort> <localPort>\r\n`
fn writeProxyV1(out: []u8, source: []const u8, local: []const u8) []const u8 {
    // source/local 形态 "ip:port"；拆分为 PROXY 头字段
    var r_ip: []const u8 = "";
    var r_port: []const u8 = "0";
    var l_ip: []const u8 = "";
    var l_port: []const u8 = "0";
    if (std.mem.lastIndexOfScalar(u8, source, ':')) |i| {
        r_ip = source[0..i];
        r_port = source[i + 1 ..];
    }
    if (std.mem.lastIndexOfScalar(u8, local, ':')) |i| {
        l_ip = local[0..i];
        l_port = local[i + 1 ..];
    }
    const is_v6 = std.mem.indexOfScalar(u8, r_ip, ':') != null;
    const fam: []const u8 = if (is_v6) "TCP6" else "TCP4";
    return std.fmt.bufPrint(out, "PROXY {s} {s} {s} {s} {s}\r\n", .{ fam, r_ip, l_ip, r_port, l_port }) catch return out[0..0];
}

/// 回落落地：dial 回落目标并双向转交（含已读首字节）。
/// conn_stream = 客户端流（VLESS 明文层）；first = 已读首字节；local = 本端地址（xver 用）。
pub fn serveFallback(
    arena: std.mem.Allocator,
    client: sock.TcpConn,
    conn_stream: stream_mod.Stream,
    first: []const u8,
    fb: *const Fallback,
    source: []const u8,
    logger: *applog.Logger,
) void {
    // dial 目标解析（仅 TCP/v4；与 sock.dialTcp 的 Phase 1 范围一致）
    var host_buf: [256]u8 = undefined;
    var host_len: usize = 0;
    var port: u16 = 0;
    if (!parseDest(fb.dest, &host_buf, &host_len, &port)) {
        logger.warning("fallback: invalid dest");
        return;
    }
    // ExponentialBackoff(5, 100)：5 次尝试，间隔 0/100/200/300/400ms
    var remote: ?sock.TcpConn = null;
    var next_delay: u32 = 0;
    var attempt: usize = 0;
    while (attempt < 5) : (attempt += 1) {
        const sa = resolveV4(arena, host_buf[0..host_len], port) orelse {
            sys.sleepMs(next_delay);
            next_delay += 100;
            continue;
        };
        if (sock.dialTcp(.{ .v4 = sa }, 16 * 1000)) |c| {
            remote = c;
            break;
        } else |_| {
            sys.sleepMs(next_delay);
            next_delay += 100;
        }
    }
    const rconn = remote orelse {
        logger.warning("fallback: failed to dial fallback dest");
        return;
    };
    defer rconn.close();

    const rctx = arena.create(stream_mod.TcpStreamCtx) catch return;
    rctx.* = .{ .conn = rconn };
    const remote_stream = rctx.stream();

    // xver：先发 PROXY v1 头（上游 postRequest；local 从 fd getsockname 取）
    if (fb.xver == 1) {
        var pb: [128]u8 = undefined;
        var lb: [48]u8 = undefined;
        const ll = client.localAddr(lb[0..]);
        const pl = writeProxyV1(&pb, source, if (ll > 0) lb[0..ll] else "0.0.0.0:0");
        if (pl.len > 0) remote_stream.writeAll(pl) catch {};
    }

    // 已读首字节原样转交（上游 first 缓冲）
    if (first.len > 0) remote_stream.writeAll(first) catch {};

    // 双向拷贝（精简版：8KB 块 + EOF 传播；空闲上限 ConnectionIdle）
    const shared = arena.create(Shared) catch return;
    shared.* = .{};
    var up = Copy{ .shared = shared, .src = conn_stream, .dst = remote_stream, .remote = rconn };
    var down = Copy{ .shared = shared, .src = remote_stream, .dst = conn_stream, .remote = rconn };
    const t1 = std.Thread.spawn(.{ .stack_size = sys.min_thread_stack }, copyMain, .{&up}) catch return;
    defer t1.join();
    const t2 = std.Thread.spawn(.{ .stack_size = sys.min_thread_stack }, copyMain, .{&down}) catch {
        shared.failed.store(true, .release);
        rconn.shutdownAll();
        return;
    };
    defer t2.join();
}

const Shared = struct {
    failed: std.atomic.Value(bool) = .init(false),
    up_done: std.atomic.Value(bool) = .init(false),
    down_done: std.atomic.Value(bool) = .init(false),
};

const Copy = struct {
    shared: *Shared,
    src: stream_mod.Stream,
    dst: stream_mod.Stream,
    remote: sock.TcpConn,
};

fn copyMain(job: *Copy) void {
    var last_activity = sys.nowMonoMs();
    var b: [buf.buffer_size]u8 = undefined;
    while (true) {
        // 空闲上限 ConnectionIdle（上游 CancelAfterInactivity(ctx, ConnectionIdle)）
        const threshold: i64 = buf.Policy.connection_idle_ms;
        job.src.setTimeout(1000);
        const n: usize = job.src.read(b[0..]) catch |e| {
            if (e == error.Timeout) {
                if (sys.nowMonoMs() - last_activity >= threshold) {
                    job.shared.failed.store(true, .release);
                    break;
                }
                continue;
            }
            job.shared.failed.store(true, .release);
            break;
        };
        if (n == 0) break; // EOF：本方向结束
        last_activity = sys.nowMonoMs();
        job.dst.setTimeout(threshold);
        job.dst.writeAll(b[0..n]) catch {
            job.shared.failed.store(true, .release);
            break;
        };
    }
    job.dst.shutdownWrite();
    if (job.shared.failed.load(.acquire)) job.remote.shutdownAll();
}

/// 解析 "host:port"（fallback dest 形态）；成功时 host_len 返回主机名长度
fn parseDest(dest: []const u8, host_out: []u8, host_len: *usize, port_out: *u16) bool {
    const i = std.mem.lastIndexOfScalar(u8, dest, ':') orelse return false;
    const host = dest[0..i];
    const p = std.fmt.parseInt(u16, dest[i + 1 ..], 10) catch return false;
    if (host.len == 0 or host.len >= host_out.len) return false;
    @memcpy(host_out[0..host.len], host);
    host_len.* = host.len;
    port_out.* = p;
    return true;
}

/// v4 解析（IP 字面量快速路径；否则走 sock.resolveV4 域名解析）
fn resolveV4(arena: std.mem.Allocator, host: []const u8, port: u16) ?sys.SockaddrIn {
    if (std.mem.indexOfScalar(u8, host, ':') != null) return null; // Phase 1 v4-only
    if (parseIpv4(host)) |octets| return sys.SockaddrIn.init(octets, port);
    const ip = sock.resolveV4(arena, host) orelse return null;
    return sys.SockaddrIn.init(ip, port);
}

fn parseIpv4(s: []const u8) ?[4]u8 {
    var out: [4]u8 = undefined;
    var it = std.mem.splitScalar(u8, s, '.');
    var i: usize = 0;
    while (it.next()) |part| {
        if (i >= 4) return null;
        out[i] = std.fmt.parseInt(u8, part, 10) catch return null;
        i += 1;
    }
    if (i != 4) return null;
    return out;
}

// ============================ 测试 ============================

test "fallback: extractPath 从 HTTP 请求行提取（上游字节级语义）" {
    // 标准 GET 请求行
    const req = "GET /some/path?q=1 HTTP/1.1\r\nHost: x\r\n\r\n";
    try std.testing.expectEqualStrings("/some/path", extractPath(req));
    // 无 query
    const req2 = "GET /index.html HTTP/1.1\r\nHost: x\r\n\r\n";
    try std.testing.expectEqualStrings("/index.html", extractPath(req2));
    // 太短（<18）→ 空
    try std.testing.expectEqualStrings("", extractPath("GET / HT"));
    // h2c 前缀（first[4]=='*'）→ 空
    const h2c = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
    try std.testing.expectEqualStrings("", extractPath(h2c));
}

test "fallback: selectFallback 三级语义（path 精确 → 默认 → null）" {
    const fbs = [_]Fallback{
        .{ .path = "/video", .dest = "127.0.0.1:81" },
        .{ .path = "", .dest = "127.0.0.1:80" }, // 默认
    };
    // path 命中
    const picked = selectFallback(&fbs, "GET /video HTTP/1.1\r\nHost: x\r\n\r\n");
    try std.testing.expect(picked != null);
    try std.testing.expectEqualStrings("127.0.0.1:81", picked.?.dest);
    // path 不命中 → 默认
    const picked2 = selectFallback(&fbs, "GET /other HTTP/1.1\r\nHost: x\r\n\r\n");
    try std.testing.expect(picked2 != null);
    try std.testing.expectEqualStrings("127.0.0.1:80", picked2.?.dest);
    // 无默认项且 path 不命中 → null（上游报错关连接）
    const fbs2 = [_]Fallback{.{ .path = "/video", .dest = "127.0.0.1:81" }};
    try std.testing.expect(selectFallback(&fbs2, "GET /x HTTP/1.1\r\nHost: y\r\n\r\n") == null);
    // 空配置 → null
    try std.testing.expect(selectFallback(&.{}, "GET / HTTP/1.1\r\n") == null);
}

test "fallback: PROXY v1 头格式（上游 xver==1）" {
    var b: [128]u8 = undefined;
    const line = writeProxyV1(&b, "1.2.3.4:5678", "10.0.0.1:19001");
    try std.testing.expectEqualStrings("PROXY TCP4 1.2.3.4 10.0.0.1 5678 19001\r\n", line);
    const line6 = writeProxyV1(&b, "2001:db8::1:443", "fe80::1:19001");
    try std.testing.expectEqualStrings("PROXY TCP6 2001:db8::1 fe80::1 443 19001\r\n", line6);
}

test "fallback: parseDest 形态" {
    var hb: [256]u8 = undefined;
    var hl: usize = 0;
    var p: u16 = 0;
    try std.testing.expect(parseDest("127.0.0.1:8080", &hb, &hl, &p));
    try std.testing.expectEqual(@as(u16, 8080), p);
    try std.testing.expectEqualStrings("127.0.0.1", hb[0..hl]);
    try std.testing.expect(!parseDest("noport", &hb, &hl, &p));
    try std.testing.expect(!parseDest(":80", &hb, &hl, &p));
}
