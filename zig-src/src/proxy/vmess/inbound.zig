//! VMess 入站协议（§5.8；对照 proxy/vmess/inbound/inbound.go + encoding/server.go
//! @ v26.10.21，AEAD-only 路径；alterId=0 唯一形态，legacy HMAC 头不存在）。
//!
//! 流程：Handshake 60s → 读 16B AuthID → 用户定位（CRC32 + ±120s 窗口 + 双池防重放，
//! validator.zig）→ OpenVMessAEADHeader（18B 密封长度 + 载荷；aead.zig，黄金向量
//! 锚定）→ 38B 明文头解析（decodeRequestHeader：IV/Key/resp/option/security/cmd/
//! 地址 + FNV 校验）→ 会话三元组去重（3 分钟）→ 响应头 38B AEAD 块（随机
//! response_header 字节）→ 分块体双向（chunk.zig；**D5：AuthenticatedLength 两方向
//! 均用请求侧 requestBodyKey/IV 派生**）→ dispatcher.dispatch。
//!
//! 错误路径：access rejected（D6：不落敏感明文）+ warning "invalid request from …"；
//! cmd != TCP（UDP/Mux）记 warning 并关闭（Phase 1）；security 仅 AES128-GCM/
//! ChaCha20-Poly1305（NONE/LEGACY 在 Go DecodeRequestBody 同样落 default 拒绝）。

const std = @import("std");
const stream_mod = @import("../../core/stream.zig");
const buf = @import("../../common/buf.zig");
const sys = @import("../../common/sys.zig");
const kdf = @import("../../crypto/kdf.zig");
const chacha_key = @import("../../crypto/chacha_key.zig");
const applog = @import("../../app/log.zig");
const dispatcher_mod = @import("../../app/dispatcher.zig");
const conf_vmess = @import("../../conf/vmess.zig");
const vmess_aead = @import("aead.zig");
const vmess_encoding = @import("encoding.zig");
const validator_mod = @import("validator.zig");
const replay_mod = @import("replay.zig");
const chunk = @import("chunk.zig");
const mux = @import("../../common/mux.zig");
const net = @import("../../common/net.zig");

const handshake_timeout_ms: i64 = 60 * 1000; // policy Handshake（表 4-1）
const max_header_payload: usize = 16384; // 上游 drainer 上限量级；放宽为硬上限（偏差登记）

pub fn handle(
    arena: std.mem.Allocator,
    gpa: std.mem.Allocator,
    conn_stream: stream_mod.Stream,
    users: []const conf_vmess.VmessClient.Built,
    filter: *replay_mod.ReplayFilter,
    history: *replay_mod.SessionHistory,
    logger: *applog.Logger,
    dsp: *dispatcher_mod.Dispatcher,
    tag: []const u8,
    source: []const u8,
) void {
    conn_stream.setTimeout(handshake_timeout_ms);

    var auth_id: [16]u8 = undefined;
    // M12 排障：握手读失败留痕（弱网慢握手/客户端放弃的区分依据）
    readFull(conn_stream, auth_id[0..]) catch |e| {
        var wb: [160]u8 = undefined;
        if (std.fmt.bufPrint(&wb, "vmess handshake read {s} from {s}", .{ @errorName(e), source })) |m| {
            logger.warning(m);
        } else |_| {}
        return;
    };

    var v = validator_mod.Validator{ .users = users, .filter = filter };
    const user = v.match(&auth_id, sys.nowUnixSecs()) catch |e| {
        const reason: []const u8 = switch (e) {
            validator_mod.MatchError.NotFound => "invalid user",
            validator_mod.MatchError.NegativeTime => "timestamp is negative",
            validator_mod.MatchError.InvalidTime => "invalid timestamp, perhaps unsynchronized time",
            validator_mod.MatchError.Replay => "replayed request",
            else => "invalid request",
        };
        reject(logger, source, reason);
        return;
    };

    // AEAD 头：18B 密封长度 + 8B conn_nonce + 载荷。
    // openHeaderLength 约定 payload = [18B 长度段][8B nonce][…]，故 26B 一次读入。
    var head_blk: [26]u8 = undefined;
    readFull(conn_stream, head_blk[0..]) catch |e| {
        var wb: [160]u8 = undefined;
        if (std.fmt.bufPrint(&wb, "vmess header read {s} from {s}", .{ @errorName(e), source })) |m| {
            logger.warning(m);
        } else |_| {}
        return;
    };
    const payload_len = vmess_aead.openHeaderLength(&head_blk, &user.cmd_key, &auth_id) catch {
        reject(logger, source, "AEAD read failed");
        return;
    };
    if (payload_len < 41 or payload_len > max_header_payload) {
        reject(logger, source, "AEAD read failed");
        return;
    }
    const sealed = arena.alloc(u8, payload_len + 16) catch return;
    readFull(conn_stream, sealed) catch return;
    // openHeaderPayload 约定：payload = [18B 长度块][8B nonce][密封载荷]
    const rest = arena.alloc(u8, 26 + payload_len + 16) catch return;
    @memcpy(rest[0..26], &head_blk);
    @memcpy(rest[26..], sealed);
    const aead_data = arena.alloc(u8, payload_len) catch return;
    _ = vmess_aead.openHeaderPayload(aead_data, rest, &user.cmd_key, &auth_id) catch {
        reject(logger, source, "AEAD read failed");
        return;
    };

    // 38B 明文头（含地址/padding/FNV 校验）
    const h = vmess_encoding.decodeRequestHeader(aead_data) catch |e| {
        const reason: []const u8 = switch (e) {
            error.HeaderTooShort => "failed to read request header",
            error.InvalidVersion => "invalid request version",
            error.FnvMismatch => "invalid auth, but this is a AEAD request",
            // Go：addrParser 解析失败被吞 → Address==nil → 末检 "invalid remote address"
            error.InvalidAddress => "invalid remote address",
        };
        reject(logger, source, reason);
        return;
    };

    // 会话三元组去重（3 分钟；Go："duplicated session id, possibly under replay
    // attack, but this is a AEAD request"）
    if (!history.addIfNotExists(user.uuid.bytes, h.request_key, h.request_iv)) {
        logger.warning("duplicated session id, possibly under replay attack, but this is a AEAD request");
        reject(logger, source, "duplicated session id");
        return;
    }

    // command：TCP 直连 dispatch；Mux 走 mux 服务端（M9）；UDP 走 freedom UDP 分支（M17）
    const is_mux = h.command == vmess_encoding.Cmd.mux;
    // M17：cmd UDP(2) 放行（对照上游 Destination() UDP 语义；载荷为 length-prefixed 包）
    const is_udp = h.command == vmess_encoding.Cmd.udp;
    // M19：同 VLESS——服务端 UDP 逻辑已验证，但客户端互通走 XUDP over mux
    // （M20 已落地于 mux 路径），裸 UDP 命令真实客户端不使用，保持拒绝。
    if (is_udp) {
        logger.warning("vmess/inbound: bare UDP command not supported (clients use XUDP over mux), connection closed");
        return;
    }
    if (!is_mux and h.command != vmess_encoding.Cmd.tcp) {
        var wb: [128]u8 = undefined;
        if (std.fmt.bufPrint(&wb, "vmess/inbound: command {d} is not supported in this build, connection closed", .{h.command})) |m| {
            logger.warning(m);
        } else |_| {}
        return;
    }
    // Mux 帧不带地址段（Go：Mux 时不解析 dest）
    const dest: ?net.Destination = if (is_mux) null else (h.dest orelse {
        reject(logger, source, "invalid remote address");
        return;
    });

    // security：仅 AES128-GCM / ChaCha20-Poly1305。
    // Go parseSecurityType + DecodeRequestHeader 末检：
    // UNKNOWN/AUTO → "unknown security type: {name}"（encoding.securityTypeName 移植）。
    const security: chunk.AeadKind = switch (h.security) {
        0x03 => .aes128_gcm,
        0x04 => .chacha20_poly1305,
        else => {
            var wb: [96]u8 = undefined;
            const reason = std.fmt.bufPrint(&wb, "unknown security type: {s}", .{vmess_encoding.securityTypeName(h.security)}) catch "unknown security type";
            reject(logger, source, reason);
            return;
        },
    };

    const masking = (h.option & vmess_encoding.RequestOption.chunk_masking) != 0;
    const global_padding = (h.option & vmess_encoding.RequestOption.global_padding) != 0;
    const auth_len = (h.option & vmess_encoding.RequestOption.authenticated_length) != 0;
    if (global_padding and !masking) {
        // Go: padding = sizeParser.(PaddingLengthGenerator) 断言失败
        reject(logger, source, "invalid option: RequestOptionGlobalPadding");
        return;
    }

    // 清 Handshake deadline（上游 SetReadDeadline(time.Time{})）
    conn_stream.setTimeout(-1);

    // 响应头 38B AEAD 块。response_header 字节**回显客户端请求头里的值**
    // （协议防中间人设计：客户端随机选 1 字节，服务端原样带回；
    // Go 侧 s.responseHeader = buffer.Byte(33) 即请求头字节）。
    // 内层 option 字节恒 0——Go transferResponse 构造的 ResponseHeader
    // 不设置 Option（inbound.go:306），EncodeResponseHeader 写 byte(header.Option)=0。
    var rbuf: [38]u8 = undefined;
    vmess_encoding.encodeResponseHeader(&rbuf, &h.request_key, &h.request_iv, h.response_header, 0);
    conn_stream.writeAll(&rbuf) catch return;

    // ---- 分块体 ----
    // 请求体：requestBodyKey/IV
    var req_shake = if (masking) chacha_key.ShakeSizeParser.init(&h.request_iv) else undefined;
    const req_size: chunk.SizeKind = if (auth_len)
        .{ .aead = .{
            .cipher = authLenCipher(security, &h.request_key),
            .nonce = chunk.ChunkNonceGen.init(&h.request_iv),
        } }
    else if (masking) .{ .shake = &req_shake } else .plain;

    var req_reader = chunk.AuthReader{
        .inner = conn_stream,
        .alloc = arena,
        .cipher = switch (security) {
            .aes128_gcm => chunk.BodyCipher.initAes128Gcm(&h.request_key),
            .chacha20_poly1305 => chunk.BodyCipher.initChacha20Poly1305(&h.request_key),
        },
        .nonce = chunk.ChunkNonceGen.init(&h.request_iv),
        .size = req_size,
        .shake = if (global_padding) &req_shake else null,
    };

    // 响应体：responseBodyKey/IV = SHA256(requestBodyKey/IV)[:16]；
    // **D5：AuthenticatedLength 尺寸段密钥/nonce 仍用请求侧 requestBodyKey/IV**
    var resp_key: [16]u8 = undefined;
    var resp_iv: [16]u8 = undefined;
    vmess_encoding.deriveResponseKeys(&resp_key, &resp_iv, &h.request_key, &h.request_iv);
    var resp_shake = if (masking) chacha_key.ShakeSizeParser.init(&resp_iv) else undefined;
    const resp_size: chunk.SizeKind = if (auth_len)
        .{ .aead = .{
            .cipher = authLenCipher(security, &h.request_key),
            .nonce = chunk.ChunkNonceGen.init(&h.request_iv),
        } }
    else if (masking) .{ .shake = &resp_shake } else .plain;

    var resp_writer = chunk.AuthWriter{
        .inner = conn_stream,
        .alloc = arena,
        .cipher = switch (security) {
            .aes128_gcm => chunk.BodyCipher.initAes128Gcm(&resp_key),
            .chacha20_poly1305 => chunk.BodyCipher.initChacha20Poly1305(&resp_key),
        },
        .nonce = chunk.ChunkNonceGen.init(&resp_iv),
        .size = resp_size,
        .shake = if (global_padding) &resp_shake else null,
    };

    var sess = buf.Session{
        .inbound_tag = tag,
        .inbound_protocol = "vmess",
        .user_email = user.email,
    };
    sess.setSource(source);

    // Go：requestDone（bodyReader→link.Writer）与 responseDone（link.Reader→
    // bodyWriter，响应头先行）并发；dispatch 同步驱动两条拷贝线程。
    // 出错（拨号失败等）→ Go 直接关连接不写终止块；干净收尾且请求方带了
    // ChunkStream 选项 → 补空终止块（inbound.go:217-218，与 outbound.go:180 对应）。
    if (is_mux) {
        // Mux：在分块体之上跑 mux 服务端（对照上游 DispatchLink → mux.Server）
        mux.serve(arena, gpa, dsp, &sess, .{ .reader = req_reader.stream(), .writer = resp_writer.stream() }, logger, source);
        if ((h.option & vmess_encoding.RequestOption.chunk_stream) != 0) {
            resp_writer.writeAll(&.{}) catch {};
        }
        return;
    }
    var udest = dest.?;
    if (is_udp) udest.network = .udp;
    dsp.dispatch(arena, &sess, udest, .{ .reader = req_reader.stream(), .writer = resp_writer.stream() }) catch return;
    if ((h.option & vmess_encoding.RequestOption.chunk_stream) != 0) {
        resp_writer.writeAll(&.{}) catch {};
    }
}

/// AuthenticatedLength 尺寸段加密体（D5：密钥/nonce 恒取请求侧 requestBodyKey/IV）
fn authLenCipher(security: chunk.AeadKind, req_key: *const [16]u8) chunk.BodyCipher {
    var k: [16]u8 = undefined;
    kdf.kdf16(&k, req_key, &.{"auth_len"});
    return switch (security) {
        .aes128_gcm => chunk.BodyCipher.initAes128Gcm(&k),
        .chacha20_poly1305 => chunk.BodyCipher.initChacha20Poly1305(&k),
    };
}

fn readFull(inner: stream_mod.Stream, out: []u8) !void {
    var off: usize = 0;
    while (off < out.len) {
        const n = try inner.read(out[off..]);
        if (n == 0) return error.EndOfStream;
        off += n;
    }
}

fn reject(logger: *applog.Logger, source: []const u8, reason: []const u8) void {
    var ab: [256]u8 = undefined;
    if (std.fmt.bufPrint(&ab, "from {s} rejected {s}", .{ source, reason })) |m| {
        logger.access(m);
    } else |_| {}
    var wb: [160]u8 = undefined;
    if (std.fmt.bufPrint(&wb, "invalid request from {s}", .{source})) |m| {
        logger.warning(m);
    } else |_| {}
}

// ============================ 测试 ============================

const testecho = @import("../../testing/echo.zig");
const sock = @import("../../common/sock.zig");
const uuid_mod = @import("../../common/uuid.zig");
const freedom_mod = @import("../freedom.zig");
const bufx = buf;
const netx = @import("../../common/net.zig");

const test_uuid_str = "de53e864-8530-4212-a3d7-c31e60b62e91";

/// auth_len 尺寸段密钥 = KDF16(requestBodyKey, "auth_len")（D5：两方向同源）
fn authLenKeyAes(req_key: *const [16]u8) [16]u8 {
    var k: [16]u8 = undefined;
    kdf.kdf16(&k, req_key, &.{"auth_len"});
    return k;
}

const ProcArgs = struct {
    arena: std.mem.Allocator,
    gpa: std.mem.Allocator,
    stream: stream_mod.Stream,
    users: []const conf_vmess.VmessClient.Built,
    filter: *replay_mod.ReplayFilter,
    history: *replay_mod.SessionHistory,
    logger: *applog.Logger,
    dsp: *dispatcher_mod.Dispatcher,
    tag: []const u8,
    source: []const u8,
};

fn handleMain(a: *ProcArgs) void {
    handle(a.arena, a.gpa, a.stream, a.users, a.filter, a.history, a.logger, a.dsp, a.tag, a.source);
}

test "vmess inbound: AEAD 全链（AuthID+密封头+分块体 D5）→ dispatch → freedom → echo" {
    const a = std.testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(a);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var pool = bufx.Pool.init(a);
    defer pool.deinit();
    var lg = applog.Logger{ .enabled = false };

    const echo = try testecho.EchoServer.start();
    defer echo.stop();

    var arena2 = std.heap.ArenaAllocator.init(a);
    defer arena2.deinit();
    const cfg = conf_vmess.VmessInboundConfig{
        .clients = &.{.{ .id = test_uuid_str, .email = "pb8lpgli" }},
    };
    const built = try cfg.build(arena2.allocator());

    const filter = try replay_mod.ReplayFilter.create(a);
    defer filter.destroy();
    const history = try replay_mod.SessionHistory.create(a);
    defer history.destroy();

    var pair = try testecho.socketpairClient(arena);
    defer {
        pair.test_side.close();
        pair.deinit();
    }

    // 客户端材料
    var req_iv: [16]u8 = undefined;
    var req_key: [16]u8 = undefined;
    for (&req_iv, 0..) |*c, i| c.* = @intCast(0x20 + i);
    for (&req_key, 0..) |*c, i| c.* = @intCast(0x30 + i);
    const resp_client_byte: u8 = 0x5A;
    // masking + global_padding + authenticated_length 全开：服务端 req_shake/resp_shake
    // 与客户端两侧独立实例同种子（request_iv/response_iv），padding 序列逐块对齐
    const option: u8 = vmess_encoding.RequestOption.chunk_masking |
        vmess_encoding.RequestOption.global_padding |
        vmess_encoding.RequestOption.authenticated_length;
    const dest = netx.Destination{ .network = .tcp, .address = .{ .ipv4 = .{ 127, 0, 0, 1 } }, .port = echo.port() };

    var hdr_plain: [512]u8 = undefined;
    const hn = vmess_encoding.encodeRequestHeader(hdr_plain[0..], &req_iv, &req_key, resp_client_byte, option, 0, 0x03, vmess_encoding.Cmd.tcp, dest, 0);

    const now = sys.nowUnixSecs();
    var auth_id: [16]u8 = undefined;
    vmess_aead.createAuthID(&auth_id, &built.users[0].cmd_key, now, .{ 1, 2, 3, 4 });
    var sealed: [1024]u8 = undefined; // hn 为运行期值 → 定长缓冲 + 切片
    vmess_aead.sealHeader(sealed[0 .. vmess_aead.min_header_len + hn], &built.users[0].cmd_key, hdr_plain[0..hn], now, .{ 1, 2, 3, 4 }, &.{ 9, 8, 7, 6, 5, 4, 3, 2 });

    var dsp = dispatcher_mod.Dispatcher{ .logger = &lg, .outbounds = .{} };
    {
        const allow = freedom_mod.BuiltRule{ .action = .allow };
        const fh = arena.create(freedom_mod.Handler) catch unreachable;
        fh.* = .{ .logger = &lg, .pool = &pool, .rules = &.{allow} };
        const handlers = arena.alloc(dispatcher_mod.OutboundHandler, 1) catch unreachable;
        handlers[0] = .{ .tag = "direct", .protocol = "freedom", .freedom = fh };
        dsp.outbounds = .{ .handlers = handlers };
    }

    var args = ProcArgs{ .arena = arena, .gpa = std.heap.smp_allocator, .stream = pair.link().reader, .users = built.users, .filter = filter, .history = history, .logger = &lg, .dsp = &dsp, .tag = "kcp-vmess", .source = "127.0.0.1:40041" };
    const th = try std.Thread.spawn(.{ .stack_size = sys.crypto_thread_stack }, handleMain, .{&args});

    // 客户端：AuthID+密封头 + 分块体（独立 SHAKE 实例）。
    // 请求走 testLink()（fds[1]）→ 服务端 link().reader（fds[0]）可读。
    try pair.test_side.writeAll(sealed[0 .. vmess_aead.min_header_len + hn]);
    var client_shake = chacha_key.ShakeSizeParser.init(&req_iv);
    var client_w = chunk.AuthWriter{
        .inner = pair.testLink().writer,
        .alloc = a,
        .cipher = chunk.BodyCipher.initAes128Gcm(&req_key),
        .nonce = chunk.ChunkNonceGen.init(&req_iv),
        .size = .{ .aead = .{
            .cipher = chunk.BodyCipher.initAes128Gcm(&authLenKeyAes(&req_key)),
            .nonce = chunk.ChunkNonceGen.init(&req_iv),
        } },
        .shake = &client_shake,
    };
    try client_w.writeAll("hello vmess d5");
    try client_w.writeAll(&.{}); // 空终止块

    // 读 38B 响应块 → 解码 → 比对 response_header
    var rb: [64]u8 = undefined;
    pair.test_side.setTimeout(5000);
    _ = try pair.test_side.read(rb[0..38]);
    const resp4 = try vmess_encoding.decodeResponseHeader(rb[0..38], &req_key, &req_iv);
    try std.testing.expectEqual(resp_client_byte, resp4[0]);

    // 读回显（响应体：resp key/iv；D5 auth_len 用请求侧材料）
    var resp_key: [16]u8 = undefined;
    var resp_iv: [16]u8 = undefined;
    vmess_encoding.deriveResponseKeys(&resp_key, &resp_iv, &req_key, &req_iv);
    var resp_shake = chacha_key.ShakeSizeParser.init(&resp_iv);
    var client_r = chunk.AuthReader{
        .inner = pair.testLink().reader,
        .alloc = a,
        .cipher = chunk.BodyCipher.initAes128Gcm(&resp_key),
        .nonce = chunk.ChunkNonceGen.init(&resp_iv),
        .size = .{ .aead = .{
            .cipher = chunk.BodyCipher.initAes128Gcm(&authLenKeyAes(&req_key)),
            .nonce = chunk.ChunkNonceGen.init(&req_iv),
        } },
        .shake = &resp_shake,
    };
    var cr = client_r.stream();
    defer client_r.deinit();
    var got: std.ArrayList(u8) = .empty;
    defer got.deinit(a);
    while (got.items.len < "hello vmess d5".len) {
        const n = try cr.read(&rb);
        if (n == 0) break;
        try got.appendSlice(a, rb[0..n]);
    }
    try std.testing.expectEqualStrings("hello vmess d5", got.items);

    // 客户端关 → 服务端收尾
    pair.test_side.shutdownWrite();
    th.join();
}
