//! WebSocket 服务端（§5.9；对照 transport/internet/websocket/{hub,connection}.go
//! + gorilla/websocket v1.5.3 在本配置路径上的可观测行为）。
//!
//! 握手（表 5-4，检查顺序 hub.go → gorilla）：
//!   Host（含 : 走 SplitHostPort 取 host，两侧小写）→ Path（剥 query + %XX 解码后
//!   精确相等）→ 0-RTT（Sec-WebSocket-Protocol 替换 +→-、/→_、删 = 后 RawURL 解码）
//!   → Connection 含 upgrade → Upgrade 含 websocket → 方法 GET → Version==13
//!   → Key base64 解码 16 字节。失败：Host/Path → 404 裸响应（空正文）；
//!   gorilla 侧 400/405 经 http.Error（状态行文本正文 + Sec-Websocket-Version:13）。
//! 有意偏差（登记）：响应不带 Date 头（Go net/http 会带；字节断言脚本须忽略它）。
//!
//! 会话：实现 Stream vtable，读侧为**可恢复状态机**（hdr/ext/mask/payload）——
//! SO_RCVTIMEO 空闲切片超时在任何位置触发都不丢帧内状态（拷贝循环的
//! ConnectionIdle 300s 语义可继续等待慢速帧）；数据帧载荷直接进 pending 连续
//! 字节流（分片重组 = 消息边界不可见，与 gorilla NextReader 观感一致）；
//! Ping→同载荷回 Pong；Close→回显对端 code（空文本）后 EOF；无 mask/RSV≠0/
//! 保留 opcode/控制帧越界/分片错序 → 协议错误（回 Close 1002）；写侧每次
//! writeAll 生成一条 Binary 消息（服务端帧不带 mask，写互斥锁防帧交错）；
//! 主动关发 Close（1000，5s 写超时）再关底层 TCP。
//! 偏差（登记）：帧载荷安全上限 1MiB（超限 Close 1009；上游无限读的 DoS 加固）。

const std = @import("std");
const frame = @import("frame.zig");
const stream_mod = @import("../../core/stream.zig");
const sys = @import("../../common/sys.zig");

const guid = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
pub const max_head_bytes: usize = 8192; // http.Server MaxHeaderBytes
const handshake_timeout_ms: i64 = 4 * 1000; // ReadHeaderTimeout / HandshakeTimeout
const write_wait_ms: i64 = 5 * 1000; // 控制帧写超时（§5.9）
const max_frame_payload: usize = 1 * 1024 * 1024;

pub const HandshakeConfig = struct {
    host: []const u8 = "", // 构建期已就绪；空 = 不校验
    path: []const u8 = "/", // 构建期已规范化
};

pub const HandshakeOutcome = union(enum) {
    ok: *Session,
    rejected, // 错误响应已写出（404/400/405）
    dropped, // 头超限/超时/畸形 → 静默断开
};

// ============================ 握手 ============================

pub fn handshake(arena: std.mem.Allocator, conn: stream_mod.Stream, cfg: HandshakeConfig) HandshakeOutcome {
    conn.setTimeout(handshake_timeout_ms);
    const head = readHead(arena, conn) orelse return .dropped;
    const req = parseRequest(arena, head) orelse return .dropped;

    // ① Host（hub.go:42，裸 404）
    if (cfg.host.len > 0 and !isValidHTTPHost(arena, req.host, cfg.host)) return reject(conn, .not_found);
    // ② Path（hub.go:47，裸 404）
    const req_path = targetPath(arena, req.target) orelse return .dropped;
    if (!std.mem.eql(u8, req_path, cfg.path)) return reject(conn, .not_found);

    // ③ 0-RTT（hub.go:55-60，Upgrade 之前；解码失败 → 忽略）
    var early: []const u8 = "";
    var echo_protocol: ?[]const u8 = null;
    if (req.protocol.len > 0) {
        if (decodeEarlyData(arena, req.protocol)) |ed| {
            if (ed.len > 0) {
                early = ed;
                echo_protocol = req.protocol;
            }
        }
    }

    // ④ gorilla v1.5.3 检查顺序
    if (!tokenContains(req.connection, "upgrade")) return reject(conn, .bad_request);
    if (!tokenContains(req.upgrade, "websocket")) return reject(conn, .bad_request);
    if (!std.mem.eql(u8, req.method, "GET")) return reject(conn, .method_not_allowed);
    if (!tokenContains(req.version, "13")) return reject(conn, .bad_request);
    if (!isValidChallengeKey(req.key)) return reject(conn, .bad_request);

    // ⑤ 101 + Accept（+ protocol 回显）
    writeUpgradeResponse(arena, conn, req.key, echo_protocol) catch return .dropped;

    const sess = arena.create(Session) catch return .dropped;
    sess.* = .{ .conn = conn, .alloc = arena, .pending = .empty };
    if (early.len > 0) {
        sess.pending.appendSlice(arena, early) catch return .dropped;
    }
    return .{ .ok = sess };
}

const RejectKind = enum { not_found, bad_request, method_not_allowed };

fn reject(conn: stream_mod.Stream, kind: RejectKind) HandshakeOutcome {
    const resp: []const u8 = switch (kind) {
        // 裸 WriteHeader（hub.go）：无正文
        .not_found => "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n",
        // http.Error（gorilla returnError）：状态行文本正文，头按 net/http 字母序
        .bad_request => "HTTP/1.1 400 Bad Request\r\nContent-Length: 12\r\nContent-Type: text/plain; charset=utf-8\r\nSec-Websocket-Version: 13\r\nX-Content-Type-Options: nosniff\r\n\r\nBad Request\n",
        .method_not_allowed => "HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 19\r\nContent-Type: text/plain; charset=utf-8\r\nSec-Websocket-Version: 13\r\nX-Content-Type-Options: nosniff\r\n\r\nMethod Not Allowed\n",
    };
    conn.writeAll(resp) catch {};
    return .rejected;
}

fn writeUpgradeResponse(arena: std.mem.Allocator, conn: stream_mod.Stream, key: []const u8, echo_protocol: ?[]const u8) !void {
    var h = std.crypto.hash.Sha1.init(.{});
    h.update(key);
    h.update(guid);
    var digest: [20]u8 = undefined;
    h.final(&digest);
    var accept_buf: [32]u8 = undefined;
    const accept = std.base64.standard.Encoder.encode(&accept_buf, &digest);

    var list: std.ArrayList(u8) = .empty;
    const p1 = try std.fmt.allocPrint(arena, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {s}\r\n", .{accept});
    list.appendSlice(arena, p1) catch return error.OutOfMemory;
    if (echo_protocol) |p| {
        const p2 = try std.fmt.allocPrint(arena, "Sec-WebSocket-Protocol: {s}\r\n", .{p});
        list.appendSlice(arena, p2) catch return error.OutOfMemory;
    }
    list.appendSlice(arena, "\r\n") catch return error.OutOfMemory;
    try conn.writeAll(list.items);
}

/// 读请求头（4s / 8192B；超限/超时/EOF → null 断开）
fn readHead(arena: std.mem.Allocator, conn: stream_mod.Stream) ?[]const u8 {
    var list: std.ArrayList(u8) = .empty;
    var chunk: [512]u8 = undefined;
    while (list.items.len < max_head_bytes) {
        const n = conn.read(&chunk) catch return null; // 超时/错误
        if (n == 0) return null; // 对端关
        list.appendSlice(arena, chunk[0..n]) catch return null;
        if (list.items.len >= 4 and std.mem.eql(u8, list.items[list.items.len - 4 ..], "\r\n\r\n")) {
            return list.items;
        }
    }
    return null; // 超限（Go: 431；本子集断开，§5.9「超限断开」）
}

const Request = struct {
    method: []const u8,
    target: []const u8,
    host: []const u8 = "",
    key: []const u8 = "",
    protocol: []const u8 = "", // Sec-WebSocket-Protocol 首值（Header.Get 语义）
    connection: []const u8 = "", // 多值逗号连接
    upgrade: []const u8 = "",
    version: []const u8 = "",
};

fn parseRequest(arena: std.mem.Allocator, head: []const u8) ?Request {
    const line_end = std.mem.indexOf(u8, head, "\r\n") orelse return null;
    const req_line = head[0..line_end];
    var parts = std.mem.splitScalar(u8, req_line, ' ');
    const method = parts.next() orelse return null;
    const target = parts.next() orelse return null;
    const proto = parts.next() orelse return null;
    if (method.len == 0 or target.len == 0 or !std.mem.startsWith(u8, proto, "HTTP/")) return null;
    if (parts.next() != null) return null; // 请求行字段数必须为 3

    var r = Request{ .method = method, .target = target };
    var conn_list: std.ArrayList(u8) = .empty;
    var up_list: std.ArrayList(u8) = .empty;
    var ver_list: std.ArrayList(u8) = .empty;

    var rest = head[line_end + 2 ..];
    while (rest.len >= 2) {
        const eol = std.mem.indexOf(u8, rest, "\r\n") orelse break;
        const line = rest[0..eol];
        rest = rest[eol + 2 ..];
        if (line.len == 0) break; // 头区终止
        const colon = std.mem.indexOfScalar(u8, line, ':') orelse continue;
        const name = line[0..colon];
        const value = std.mem.trim(u8, line[colon + 1 ..], " \t");
        if (eqlIgnoreCase(name, "host")) {
            if (r.host.len == 0) r.host = value;
        } else if (eqlIgnoreCase(name, "sec-websocket-key")) {
            if (r.key.len == 0) r.key = value;
        } else if (eqlIgnoreCase(name, "sec-websocket-protocol")) {
            if (r.protocol.len == 0) r.protocol = value;
        } else if (eqlIgnoreCase(name, "connection")) {
            joinValue(arena, &conn_list, value) catch return null;
        } else if (eqlIgnoreCase(name, "upgrade")) {
            joinValue(arena, &up_list, value) catch return null;
        } else if (eqlIgnoreCase(name, "sec-websocket-version")) {
            joinValue(arena, &ver_list, value) catch return null;
        }
    }
    r.connection = conn_list.items;
    r.upgrade = up_list.items;
    r.version = ver_list.items;
    return r;
}

fn joinValue(arena: std.mem.Allocator, list: *std.ArrayList(u8), value: []const u8) !void {
    if (list.items.len > 0) try list.append(arena, ',');
    try list.appendSlice(arena, value);
}

fn eqlIgnoreCase(a: []const u8, b: []const u8) bool {
    return std.ascii.eqlIgnoreCase(a, b);
}

/// gorilla tokenListContainsValue：逗号分隔，trim 空白，大小写不敏感逐项比对
fn tokenContains(values: []const u8, needle: []const u8) bool {
    var it = std.mem.splitScalar(u8, values, ',');
    while (it.next()) |raw| {
        const t = std.mem.trim(u8, raw, " \t");
        if (t.len == 0) continue;
        if (std.ascii.eqlIgnoreCase(t, needle)) return true;
    }
    return false;
}

/// internet.IsValidHTTPHost：两侧小写；request 含 ":" 时按 SplitHostPort 取 host
fn isValidHTTPHost(arena: std.mem.Allocator, request: []const u8, config: []const u8) bool {
    const r = lowerDupe(arena, request) catch return false;
    const c = lowerDupe(arena, config) catch return false;
    if (std.mem.indexOfScalar(u8, r, ':') != null) {
        const h = splitHostPort(r) orelse "";
        return std.mem.eql(u8, h, c);
    }
    return std.mem.eql(u8, r, c);
}

fn lowerDupe(arena: std.mem.Allocator, s: []const u8) ![]u8 {
    const out = try arena.alloc(u8, s.len);
    for (s, 0..) |ch, i| out[i] = std.ascii.toLower(ch);
    return out;
}

/// net.SplitHostPort 的 host 部分（失败 → null；Go 错误路径 h=""）
fn splitHostPort(s: []const u8) ?[]const u8 {
    if (s.len > 0 and s[0] == '[') {
        const close = std.mem.indexOfScalar(u8, s, ']') orelse return null;
        const rest = s[close + 1 ..];
        if (rest.len == 0 or rest[0] != ':') return null;
        return s[1..close];
    }
    const last = std.mem.lastIndexOfScalar(u8, s, ':') orelse return null;
    const host = s[0..last];
    if (std.mem.indexOfScalar(u8, host, ':') != null) return null; // too many colons
    return host;
}

/// 请求目标 → URL.Path 语义（绝对形式剥 authority；剥 query；%XX 解码；非法转义 → null）
fn targetPath(arena: std.mem.Allocator, target: []const u8) ?[]const u8 {
    var t = target;
    if (std.mem.startsWith(u8, t, "http://") or std.mem.startsWith(u8, t, "https://")) {
        const scheme_end = std.mem.indexOf(u8, t, "://").? + 3;
        const after = t[scheme_end..];
        const slash = std.mem.indexOfScalar(u8, after, '/') orelse return "";
        t = after[slash..];
    }
    const q = std.mem.indexOfScalar(u8, t, '?') orelse t.len;
    return percentDecode(arena, t[0..q]);
}

fn percentDecode(arena: std.mem.Allocator, s: []const u8) ?[]const u8 {
    const out = arena.alloc(u8, s.len) catch return null;
    var n: usize = 0;
    var i: usize = 0;
    while (i < s.len) {
        if (s[i] == '%') {
            if (i + 2 >= s.len) return null;
            const hi = hexVal(s[i + 1]) orelse return null;
            const lo = hexVal(s[i + 2]) orelse return null;
            out[n] = (hi << 4) | lo;
            i += 3;
        } else {
            out[n] = s[i];
            i += 1;
        }
        n += 1;
    }
    return out[0..n];
}

fn hexVal(c: u8) ?u8 {
    return switch (c) {
        '0'...'9' => c - '0',
        'a'...'f' => c - 'a' + 10,
        'A'...'F' => c - 'A' + 10,
        else => null,
    };
}

/// hub.go replacer（+→-、/→_、=删除）+ base64 RawURL 解码；失败/空 → null（忽略）
fn decodeEarlyData(arena: std.mem.Allocator, value: []const u8) ?[]const u8 {
    const tmp = arena.alloc(u8, value.len) catch return null;
    var n: usize = 0;
    for (value) |c| {
        const m: u8 = switch (c) {
            '+' => '-',
            '/' => '_',
            '=' => continue,
            else => c,
        };
        tmp[n] = m;
        n += 1;
    }
    const dec = std.base64.url_safe_no_pad.Decoder;
    const sz = dec.calcSizeForSlice(tmp[0..n]) catch return null;
    if (sz == 0) return null;
    const out = arena.alloc(u8, sz) catch return null;
    dec.decode(out, tmp[0..n]) catch return null;
    return out;
}

/// gorilla isValidChallengeKey：base64 解码后必须 16 字节
fn isValidChallengeKey(key: []const u8) bool {
    if (key.len == 0) return false;
    const dec = std.base64.standard.Decoder;
    const sz = dec.calcSizeForSlice(key) catch return false;
    if (sz != 16) return false;
    var dec_buf: [16]u8 = undefined;
    dec.decode(&dec_buf, key) catch return false;
    return true;
}

// ============================ 会话（可恢复读状态机） ============================

pub const Session = struct {
    conn: stream_mod.Stream,
    alloc: std.mem.Allocator,
    pending: std.ArrayList(u8), // 待消费载荷（含 0-RTT early data）
    peer_closed: bool = false,
    we_closed: bool = false,
    broken: bool = false, // 协议错误/帧中 EOF，连接不可再用
    write_mu: sys.Mutex = .{}, // 头+载荷两段写的帧交错防护

    // 读状态机
    state: ReadState = .hdr,
    hdr: [2]u8 = .{ 0, 0 },
    hdr_have: u8 = 0,
    hdr_masked: bool = false,
    ext: [8]u8 = .{ 0, 0, 0, 0, 0, 0, 0, 0 },
    ext_need: u8 = 0,
    ext_have: u8 = 0,
    key: [4]u8 = .{ 0, 0, 0, 0 },
    key_have: u8 = 0,
    cur_opcode: u8 = 0,
    cur_fin: bool = false,
    cur_len: u64 = 0,
    payload_have: u64 = 0,
    ctl: std.ArrayList(u8) = .empty, // 控制帧载荷
    frag_active: bool = false, // 分片消息进行中（FIN=0 已见）

    const ReadState = enum { hdr, ext, mask, payload };

    pub fn stream(self: *Session) stream_mod.Stream {
        return .{
            .ctx = self,
            .readFn = readImpl,
            .writeAllFn = writeAllImpl,
            .closeFn = closeImpl,
            .setTimeoutFn = setTimeoutImpl,
            .shutdownWriteFn = shutdownWriteImpl,
        };
    }

    /// 心跳能力（connection.go heartbeatPeriod goroutine；本配置 0 不启用）
    pub fn startHeartbeat(self: *Session, period_secs: u32) void {
        if (period_secs == 0) return;
        const th = std.Thread.spawn(.{ .stack_size = sys.min_thread_stack }, heartbeatMain, .{ self, period_secs }) catch return;
        th.detach();
    }

    fn heartbeatMain(self: *Session, period_secs: u32) void {
        while (!self.we_closed and !self.peer_closed and !self.broken) {
            sys.sleepMs(@as(u64, period_secs) * 1000);
            if (self.we_closed or self.peer_closed or self.broken) return;
            self.writeControl(frame.opcode_ping, &.{}) catch return;
        }
    }

    fn readImpl(ctx: *anyopaque, out: []u8) anyerror!usize {
        const self: *Session = @ptrCast(@alignCast(ctx));
        while (true) {
            if (self.pending.items.len > 0) {
                const n = @min(out.len, self.pending.items.len);
                @memcpy(out[0..n], self.pending.items[0..n]);
                const rest = self.pending.items.len - n;
                std.mem.copyForwards(u8, self.pending.items[0..rest], self.pending.items[n..]);
                self.pending.shrinkRetainingCapacity(rest);
                return n;
            }
            if (self.peer_closed or self.we_closed or self.broken) return 0;
            try self.pump();
        }
    }

    /// 状态机推进：直到 pending 有增量数据 / 对端关 / 错误。
    /// 任何位置的超时都不丢状态（ConnectionIdle 空闲切片可安全重入）。
    fn pump(self: *Session) anyerror!void {
        while (!self.peer_closed) {
            switch (self.state) {
                .hdr => {
                    const n = try self.readSome(self.hdr[self.hdr_have..2]);
                    if (n == 0) {
                        // 对端关闭：帧边界（hdr_have==0）= 干净 EOF；
                        // 帧头读一半被关 = 连接断（broken，消费方见 EOF）
                        if (self.hdr_have == 0) self.peer_closed = true else self.broken = true;
                        return;
                    }
                    self.hdr_have += @intCast(n);
                    if (self.hdr_have == 2) {
                        const h = frame.parseBase(self.hdr[0], self.hdr[1]);
                        if ((self.hdr[0] & 0x70) != 0) return self.protocolError(); // RSV≠0
                        if ((h.opcode & 0x8) != 0) {
                            if (!h.fin or h.length > 125) return self.protocolError(); // 控制帧越界
                        } else if (h.opcode > frame.opcode_binary) {
                            return self.protocolError(); // 保留 opcode
                        }
                        self.cur_opcode = h.opcode;
                        self.cur_fin = h.fin;
                        self.hdr_masked = h.masked;
                        self.payload_have = 0;
                        self.ctl.clearRetainingCapacity();
                        if (h.length == 126) {
                            self.state = .ext;
                            self.ext_need = 2;
                            self.ext_have = 0;
                        } else if (h.length == 127) {
                            self.state = .ext;
                            self.ext_need = 8;
                            self.ext_have = 0;
                        } else {
                            self.cur_len = h.length;
                            try self.afterHeader();
                            if (self.pending.items.len > 0 or self.peer_closed) return;
                        }
                    }
                },
                .ext => {
                    const n = try self.readSome(self.ext[self.ext_have..self.ext_need]);
                    if (n == 0) {
                        if (self.ext_have == 0) self.peer_closed = true else self.broken = true;
                        return;
                    }
                    self.ext_have += @intCast(n);
                    if (self.ext_have == self.ext_need) {
                        self.cur_len = if (self.ext_need == 2)
                            std.mem.readInt(u16, self.ext[0..2], .big)
                        else
                            std.mem.readInt(u64, self.ext[0..8], .big);
                        if (self.cur_len > max_frame_payload) {
                            self.sendClose(frame.close_too_big) catch {};
                            self.broken = true;
                            return error.TooBig;
                        }
                        try self.afterHeader();
                        if (self.pending.items.len > 0 or self.peer_closed) return;
                    }
                },
                .mask => {
                    const n = try self.readSome(self.key[self.key_have..4]);
                    if (n == 0) {
                        if (self.key_have == 0) self.peer_closed = true else self.broken = true;
                        return;
                    }
                    self.key_have += @intCast(n);
                    if (self.key_have == 4) {
                        self.state = .payload;
                        // 分片定序已在 afterHeader（mask 校验同点）完成，不重复
                        if (self.cur_len == 0) {
                            try self.frameComplete();
                            if (self.pending.items.len > 0 or self.peer_closed) return;
                        }
                    }
                },
                .payload => {
                    if (self.cur_len == 0) {
                        try self.frameComplete();
                        if (self.pending.items.len > 0 or self.peer_closed) return;
                        continue;
                    }
                    var chunk: [4096]u8 = undefined;
                    const want: usize = @intCast(@min(chunk.len, self.cur_len - self.payload_have));
                    const n = try self.readSome(chunk[0..want]);
                    if (n == 0) {
                        self.broken = true;
                        return error.Closed; // 帧中 EOF
                    }
                    frame.unmask(chunk[0..n], self.key, @intCast(self.payload_have & 3));
                    self.payload_have += n;
                    if ((self.cur_opcode & 0x8) != 0) {
                        self.ctl.appendSlice(self.alloc, chunk[0..n]) catch return error.OutOfMemory;
                    } else {
                        self.pending.appendSlice(self.alloc, chunk[0..n]) catch return error.OutOfMemory;
                    }
                    if (self.payload_have == self.cur_len) {
                        try self.frameComplete();
                        if (self.pending.items.len > 0 or self.peer_closed) return;
                    } else {
                        return; // 有增量数据 → 先交消费方
                    }
                },
            }
        }
    }

    /// 基本头/扩展长度读完后的公共收尾：mask 校验 + 数据帧分片定序
    fn afterHeader(self: *Session) anyerror!void {
        if (!self.hdr_masked) return self.protocolError(); // 客户端帧必须 mask
        self.state = .mask;
        self.key_have = 0;
        if ((self.cur_opcode & 0x8) == 0) {
            if (self.cur_opcode == frame.opcode_continuation) {
                if (!self.frag_active) return self.protocolError();
                if (self.cur_fin) self.frag_active = false;
            } else {
                if (self.frag_active) return self.protocolError();
                if (!self.cur_fin) self.frag_active = true;
            }
        }
    }

    fn frameComplete(self: *Session) anyerror!void {
        self.state = .hdr;
        self.hdr_have = 0;
        if ((self.cur_opcode & 0x8) == 0) return; // 数据帧：载荷已在 pending
        switch (self.cur_opcode) {
            frame.opcode_close => {
                var code: u16 = frame.close_no_status;
                if (self.ctl.items.len == 1) return self.protocolError(); // 长度 1 非法
                if (self.ctl.items.len >= 2) {
                    code = std.mem.readInt(u16, self.ctl.items[0..2], .big);
                    if (!frame.isValidReceivedCloseCode(code)) return self.protocolError();
                }
                self.sendClose(code) catch {}; // 回显对端 code（空文本）
                self.peer_closed = true;
            },
            frame.opcode_ping => try self.writeControl(frame.opcode_pong, self.ctl.items),
            frame.opcode_pong => {}, // 忽略
            else => return self.protocolError(),
        }
    }

    fn readSome(self: *Session, into: []u8) anyerror!usize {
        return self.conn.read(into) catch |e| switch (e) {
            error.ConnectionResetByPeer, error.BrokenPipe => error.Closed,
            else => e,
        };
    }

    fn protocolError(self: *Session) anyerror {
        self.sendClose(frame.close_protocol_error) catch {};
        self.broken = true;
        return error.Protocol;
    }

    /// 写控制帧（5s 写超时，WriteControl 语义）
    fn writeControl(self: *Session, opcode: u4, payload: []const u8) anyerror!void {
        self.conn.setTimeout(write_wait_ms);
        try self.writeFrame(opcode, payload);
    }

    /// 写一条帧（服务端帧不带 mask；互斥防头/载荷两段写被并发帧插入）
    fn writeFrame(self: *Session, opcode: u4, payload: []const u8) anyerror!void {
        var hdr: [10]u8 = undefined;
        const n = frame.encodeHeader(true, opcode, payload.len, &hdr);
        self.write_mu.lock();
        defer self.write_mu.unlock();
        // M22：头 + 载荷一次 writev（原为两次 sendto，1MiB = 256 次 syscall → 128 次）
        try self.conn.writeAllVec(&.{ hdr[0..n], payload });
    }

    fn sendClose(self: *Session, code: u16) anyerror!void {
        if (self.we_closed) return;
        self.we_closed = true;
        var pl_buf: [2]u8 = undefined;
        const pl = frame.formatClosePayload(&pl_buf, code);
        try self.writeControl(frame.opcode_close, pl);
    }

    fn writeAllImpl(ctx: *anyopaque, data: []const u8) anyerror!void {
        const self: *Session = @ptrCast(@alignCast(ctx));
        if (self.peer_closed or self.we_closed or self.broken) return error.NotOpen;
        // 每次 write 生成一条 Binary 消息（与上游 WriteMessage 一致）
        try self.writeFrame(frame.opcode_binary, data);
    }

    fn closeImpl(ctx: *anyopaque) void {
        const self: *Session = @ptrCast(@alignCast(ctx));
        if (!self.peer_closed and !self.we_closed and !self.broken) {
            self.sendClose(frame.close_normal) catch {}; // 主动关：Close 帧（5s 超时）后关 TCP
        }
        self.conn.close();
    }

    fn setTimeoutImpl(ctx: *anyopaque, ms: i64) void {
        const self: *Session = @ptrCast(@alignCast(ctx));
        self.conn.setTimeout(ms);
    }

    fn shutdownWriteImpl(ctx: *anyopaque) void {
        const self: *Session = @ptrCast(@alignCast(ctx));
        self.conn.shutdownWrite();
    }
};

// ============================ 测试 ============================

const testecho = @import("../../testing/echo.zig");
const sock = @import("../../common/sock.zig");
const buf = @import("../../common/buf.zig");
const applog = @import("../../app/log.zig");
const dispatcher_mod = @import("../../app/dispatcher.zig");
const freedom_mod = @import("../../proxy/freedom.zig");
const net = @import("../../common/net.zig");

/// 构造客户端帧（masked；测试载荷 <126）
fn maskedFrame(arena: std.mem.Allocator, fin: bool, opcode: u4, payload: []const u8) []const u8 {
    var list: std.ArrayList(u8) = .empty;
    const f: u8 = @as(u8, if (fin) 0x80 else 0);
    list.append(arena, f | @as(u8, opcode)) catch unreachable;
    list.append(arena, 0x80 | @as(u8, @intCast(payload.len))) catch unreachable;
    const key = [4]u8{ 0x11, 0x22, 0x33, 0x44 };
    list.appendSlice(arena, &key) catch unreachable;
    for (payload, 0..) |c, i| {
        list.append(arena, c ^ key[i & 3]) catch unreachable;
    }
    return list.items;
}

/// 测试侧消费 101 响应（握手成功后的服务端首帧输出），并断言状态行
fn expect101(pair: *testecho.ClientPair) !void {
    var rb: [256]u8 = undefined;
    var acc: std.ArrayList(u8) = .empty;
    pair.test_side.setTimeout(2000);
    while (std.mem.indexOf(u8, acc.items, "\r\n\r\n") == null) {
        const n = try pair.test_side.read(&rb);
        if (n == 0) return error.UnexpectedEof;
        try acc.appendSlice(std.testing.allocator, rb[0..n]);
    }
    defer acc.deinit(std.testing.allocator);
    if (!std.mem.startsWith(u8, acc.items, "HTTP/1.1 101 Switching Protocols\r\n")) {
        return error.NotUpgraded;
    }
}

test "handshake: 404 host / 404 path / 400 / 405 / 101 字节级断言" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const cases = [_]struct {
        req: []const u8,
        expect: []const u8,
    }{
        // Host 不匹配 → 404 空正文
        .{
            .req = "GET /free HTTP/1.1\r\nHost: wrong.example.com\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n",
            .expect = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n",
        },
        // Path 不匹配 → 404（Host 带端口走 SplitHostPort 语义匹配）
        .{
            .req = "GET /wrong HTTP/1.1\r\nHost: ltetp.tv189.com:8080\r\nConnection: keep-alive, Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n",
            .expect = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n",
        },
        // Connection 缺 upgrade 项 → 400（gorilla 在 Method 之前）
        .{
            .req = "GET /free HTTP/1.1\r\nHost: ltetp.tv189.com\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n",
            .expect = "HTTP/1.1 400 Bad Request\r\nContent-Length: 12\r\nContent-Type: text/plain; charset=utf-8\r\nSec-Websocket-Version: 13\r\nX-Content-Type-Options: nosniff\r\n\r\nBad Request\n",
        },
        // 方法非 GET → 405
        .{
            .req = "POST /free HTTP/1.1\r\nHost: ltetp.tv189.com\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n",
            .expect = "HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 19\r\nContent-Type: text/plain; charset=utf-8\r\nSec-Websocket-Version: 13\r\nX-Content-Type-Options: nosniff\r\n\r\nMethod Not Allowed\n",
        },
        // Version 非 13 → 400
        .{
            .req = "GET /free HTTP/1.1\r\nHost: ltetp.tv189.com\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 8\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n",
            .expect = "HTTP/1.1 400 Bad Request\r\nContent-Length: 12\r\nContent-Type: text/plain; charset=utf-8\r\nSec-Websocket-Version: 13\r\nX-Content-Type-Options: nosniff\r\n\r\nBad Request\n",
        },
        // Key 非 16 字节 → 400
        .{
            .req = "GET /free HTTP/1.1\r\nHost: ltetp.tv189.com\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: shortkey\r\n\r\n",
            .expect = "HTTP/1.1 400 Bad Request\r\nContent-Length: 12\r\nContent-Type: text/plain; charset=utf-8\r\nSec-Websocket-Version: 13\r\nX-Content-Type-Options: nosniff\r\n\r\nBad Request\n",
        },
    };

    const cfg = HandshakeConfig{ .host = "ltetp.tv189.com", .path = "/free" };
    for (cases) |c| {
        var pair = try testecho.socketpairClient(arena);
        defer {
            pair.test_side.close();
            pair.deinit();
        }
        try pair.test_side.writeAll(c.req);
        const outcome = handshake(arena, pair.link().reader, cfg);
        try std.testing.expect(outcome == .rejected);
        var rb: [512]u8 = undefined;
        pair.test_side.setTimeout(2000);
        const n = try pair.test_side.read(&rb);
        try std.testing.expectEqualStrings(c.expect, rb[0..n]);
    }
}

test "handshake: 101 升级 + RFC 6455 Accept 值 + 0-RTT 回显与首读" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var pair = try testecho.socketpairClient(arena);
    defer {
        pair.test_side.close();
        pair.deinit();
    }
    // Sec-WebSocket-Protocol: base64url("HELLO-RTT") = "SEVMTE8tUlRU"
    const req = "GET /free?ed=2048 HTTP/1.1\r\nHost: LTETP.TV189.COM\r\nConnection: keep-alive, Upgrade\r\nUpgrade: WebSocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Protocol: SEVMTE8tUlRU\r\n\r\n";
    try pair.test_side.writeAll(req);

    const cfg = HandshakeConfig{ .host = "ltetp.tv189.com", .path = "/free" };
    const outcome = handshake(arena, pair.link().reader, cfg);
    const sess = outcome.ok;
    defer sess.conn.close();

    var rb: [512]u8 = undefined;
    pair.test_side.setTimeout(2000);
    const n = try pair.test_side.read(&rb);
    // RFC 6455 §1.3 示例：key=dGhlIHNhbXBsZSBub25jZQ== → Accept=s3pPLMBiTxaQ9kYGzzhZRbK+xOo=
    const expect = "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\nSec-WebSocket-Protocol: SEVMTE8tUlRU\r\n\r\n";
    try std.testing.expectEqualStrings(expect, rb[0..n]);

    // 0-RTT early data 先于帧可读
    var pb: [32]u8 = undefined;
    var sn = sess.stream();
    const en = try sn.read(&pb);
    try std.testing.expectEqualStrings("HELLO-RTT", pb[0..en]);

    // masked binary 帧 → 读出载荷
    const mf = maskedFrame(arena, true, frame.opcode_binary, "ws-payload");
    try pair.test_side.writeAll(mf);
    var db: [64]u8 = undefined;
    const dn = try sn.read(&db);
    try std.testing.expectEqualStrings("ws-payload", db[0..dn]);
}

test "session: 分片重组 + ping→pong 回显 + close 回显 code" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var pair = try testecho.socketpairClient(arena);
    defer {
        pair.test_side.close();
        pair.deinit();
    }
    try pair.test_side.writeAll("GET / HTTP/1.1\r\nHost: h\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n");
    const sess = handshake(arena, pair.link().reader, .{}).ok;
    var sn = sess.stream();
    try expect101(&pair); // 先消费 101 再读服务端帧

    // 分片：binary("frag-") fin=0 + 控制帧 ping 穿插 + continuation("one") fin=1。
    // 服务端按到达顺序流式交付（gorilla NextReader 观感），不保证重组消息一次读全。
    try pair.test_side.writeAll(maskedFrame(arena, false, frame.opcode_binary, "frag-"));
    try pair.test_side.writeAll(maskedFrame(arena, true, frame.opcode_ping, "hi"));
    try pair.test_side.writeAll(maskedFrame(arena, true, frame.opcode_continuation, "one"));
    var acc: [16]u8 = undefined;
    var got: usize = 0;
    while (got < 8) {
        const n = try sn.read(acc[got..]);
        if (n == 0) break;
        got += n;
    }
    try std.testing.expectEqualStrings("frag-one", acc[0..got]);

    // 服务端已自动回 pong（服务端帧无 mask）
    pair.test_side.setTimeout(2000);
    var pb: [16]u8 = undefined;
    const pn = try pair.test_side.read(&pb);
    try std.testing.expectEqualSlices(u8, &.{ 0x8A, 0x02, 'h', 'i' }, pb[0..pn]);

    // 对端 close 1001 → 服务端回显 1001 → read EOF
    try pair.test_side.writeAll(maskedFrame(arena, true, frame.opcode_close, &.{ 0x03, 0xE9 }));
    try std.testing.expectEqual(@as(usize, 0), try sn.read(&acc));
    const cn = try pair.test_side.read(&pb);
    try std.testing.expectEqualSlices(u8, &.{ 0x88, 0x02, 0x03, 0xE9 }, pb[0..cn]);
    try std.testing.expect(sess.peer_closed);
}

test "session: 无 mask 帧协议错误（回 close 1002）" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var pair = try testecho.socketpairClient(arena);
    defer {
        pair.test_side.close();
        pair.deinit();
    }
    try pair.test_side.writeAll("GET / HTTP/1.1\r\nHost: h\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n");
    const sess = handshake(arena, pair.link().reader, .{}).ok;
    var sn = sess.stream();
    try expect101(&pair); // 先消费 101

    // 无 mask 的 binary 帧：0x82 0x02 'x' 'y'
    try pair.test_side.writeAll(&.{ 0x82, 0x02, 'x', 'y' });
    var rb: [16]u8 = undefined;
    try std.testing.expectError(error.Protocol, sn.read(&rb));
    pair.test_side.setTimeout(2000);
    var pb: [16]u8 = undefined;
    const n = try pair.test_side.read(&pb);
    try std.testing.expectEqualSlices(u8, &.{ 0x88, 0x02, 0x03, 0xEA }, pb[0..n]); // close 1002
}

test "session: 主动关发 Close 1000（5s 写超时）后关 TCP" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var pair = try testecho.socketpairClient(arena);
    defer {
        pair.test_side.close();
        pair.deinit();
    }
    try pair.test_side.writeAll("GET / HTTP/1.1\r\nHost: h\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n");
    const sess = handshake(arena, pair.link().reader, .{}).ok;
    var sn = sess.stream();
    try expect101(&pair); // 先消费 101
    sn.close(); // 主动关

    pair.test_side.setTimeout(2000);
    var pb: [16]u8 = undefined;
    const n = try pair.test_side.read(&pb);
    try std.testing.expectEqualSlices(u8, &.{ 0x88, 0x02, 0x03, 0xE8 }, pb[0..n]); // close 1000
    // 随后 TCP EOF
    const n2 = try pair.test_side.read(&pb);
    try std.testing.expectEqual(@as(usize, 0), n2);
}

// ---- 端到端：WS 会话 → dispatcher → freedom → echo（测试侧扮 WS 客户端） ----

const WsProcArgs = struct {
    d: *dispatcher_mod.Dispatcher,
    arena: std.mem.Allocator,
    sess: *buf.Session,
    dest: net.Destination,
    ws: stream_mod.Stream,
};

fn wsDispatchMain(a: *WsProcArgs) void {
    a.d.dispatch(a.arena, a.sess, a.dest, .{ .reader = a.ws, .writer = a.ws }) catch {};
}

test "e2e: WS over socketpair → dispatcher → freedom → echo → WS 回读" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var pool = buf.Pool.init(std.testing.allocator);
    defer pool.deinit();
    var lg = applog.Logger{ .enabled = false };

    const echo = try testecho.EchoServer.start();
    defer echo.stop();

    var pair = try testecho.socketpairClient(arena);
    defer {
        pair.test_side.close();
        pair.deinit();
    }
    try pair.test_side.writeAll("GET / HTTP/1.1\r\nHost: h\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n");
    const outcome = handshake(arena, pair.link().reader, .{});
    const ws_sess = outcome.ok;
    const ws_stream = ws_sess.stream();
    try expect101(&pair); // 先消费 101

    const allow = freedom_mod.BuiltRule{ .action = .allow };
    var fh = freedom_mod.Handler{ .logger = &lg, .pool = &pool, .rules = &.{allow} };
    const handlers = [_]dispatcher_mod.OutboundHandler{.{ .tag = "direct", .protocol = "freedom", .freedom = &fh }};
    var d = dispatcher_mod.Dispatcher{ .logger = &lg, .outbounds = .{ .handlers = handlers[0..] } };

    var bsess = buf.Session{};
    bsess.inbound_tag = "inbound-19001";
    bsess.inbound_protocol = "vless";
    bsess.setSource("127.0.0.1:40021");

    const dest = net.Destination{ .network = .tcp, .address = .{ .ipv4 = .{ 127, 0, 0, 1 } }, .port = echo.port() };
    var args = WsProcArgs{ .d = &d, .arena = arena, .sess = &bsess, .dest = dest, .ws = ws_stream };
    const th = try std.Thread.spawn(.{ .stack_size = sys.min_thread_stack }, wsDispatchMain, .{&args});

    // 客户端：masked 分片 "ws-" + "e2e" → echo → 服务端 Binary 帧（无 mask）回读。
    // 帧粒度跟随读块切分（上游同）：循环读帧直到累积出 "ws-e2e"。
    try pair.test_side.writeAll(maskedFrame(arena, false, frame.opcode_binary, "ws-"));
    try pair.test_side.writeAll(maskedFrame(arena, true, frame.opcode_continuation, "e2e"));
    pair.test_side.setTimeout(5000);
    var got: [8]u8 = undefined;
    var got_len: usize = 0;
    var hdr: [2]u8 = undefined;
    while (got_len < 6) {
        try readExact(&pair.test_side, &hdr);
        try std.testing.expectEqual(@as(u8, 0x82), hdr[0] & 0x8F); // FIN+binary
        const ln: usize = hdr[1]; // 测试载荷 <126
        try readExact(&pair.test_side, got[got_len..][0..ln]);
        got_len += ln;
    }
    try std.testing.expectEqualStrings("ws-e2e", got[0..got_len]);

    // 客户端 close 1000 → 服务端回显 → dispatch 线程收尾。
    // 注意：echo 的残余数据帧可能与 Close 帧同批到达/先到（帧粒度跟随读块切分），
    // 所以按帧解析直到见到 Close（M9 修 flaky：原实现断言"下一批 4 字节恰为 Close 帧"）。
    try pair.test_side.writeAll(maskedFrame(arena, true, frame.opcode_close, &.{ 0x03, 0xE8 }));
    var acc: [128]u8 = undefined;
    var acc_len: usize = 0;
    var saw_close = false;
    var close_code: u16 = 0;
    while (!saw_close) {
        const n = try pair.test_side.read(acc[acc_len..]);
        if (n == 0) break;
        acc_len += n;
        var pos: usize = 0;
        while (pos + 2 <= acc_len) {
            const op = acc[pos] & 0x0F;
            const ln: usize = acc[pos + 1] & 0x7F;
            if (pos + 2 + ln > acc_len) break;
            if (op == frame.opcode_close) {
                saw_close = true;
                if (ln >= 2) close_code = (@as(u16, acc[pos + 2]) << 8) | acc[pos + 3];
            }
            pos += 2 + ln;
        }
        if (pos > 0) {
            std.mem.copyForwards(u8, acc[0 .. acc_len - pos], acc[pos..acc_len]);
            acc_len -= pos;
        }
    }
    try std.testing.expect(saw_close);
    try std.testing.expectEqual(@as(u16, 1000), close_code); // 回显对端 close code
    th.join();
}

fn readExact(conn: *const sock.TcpConn, out: []u8) !void {
    var off: usize = 0;
    while (off < out.len) {
        const n = try conn.read(out[off..]);
        if (n == 0) return error.UnexpectedEof;
        off += n;
    }
}

// ---- 握手纯函数单测 ----

test "isValidHTTPHost（SplitHostPort 语义）" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    try std.testing.expect(isValidHTTPHost(arena, "ltetp.tv189.com", "ltetp.tv189.com"));
    try std.testing.expect(isValidHTTPHost(arena, "LTETP.TV189.COM", "ltetp.tv189.com"));
    try std.testing.expect(isValidHTTPHost(arena, "ltetp.tv189.com:8080", "ltetp.tv189.com"));
    try std.testing.expect(isValidHTTPHost(arena, "[::1]:8080", "::1"));
    try std.testing.expect(!isValidHTTPHost(arena, "wrong.com", "ltetp.tv189.com"));
    try std.testing.expect(!isValidHTTPHost(arena, "a:b:c", "a")); // SplitHostPort 失败 → ""
    try std.testing.expect(!isValidHTTPHost(arena, "::1", "::1")); // 裸 v6 无括号 → 失败 → ""
    try std.testing.expect(!isValidHTTPHost(arena, "ltetp.tv189.com.evil.com", "ltetp.tv189.com"));
}

test "targetPath（query 剥离 + %XX 解码 + 绝对形式）" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    try std.testing.expectEqualStrings("/free", targetPath(arena, "/free?ed=2048").?);
    try std.testing.expectEqualStrings("/a b", targetPath(arena, "/a%20b").?);
    try std.testing.expectEqualStrings("/free", targetPath(arena, "http://x.com/free?q=1").?);
    try std.testing.expect(targetPath(arena, "/bad%zz") == null);
}

test "decodeEarlyData（+→-、/→_、=删除，RawURL 解码）" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    try std.testing.expectEqualStrings("early", decodeEarlyData(arena, "ZWFybHk=").?);
    try std.testing.expectEqualStrings("early", decodeEarlyData(arena, "ZWFybHk").?);
    // std base64 含 '+' 的形态 → 替换后 url-safe 解码
    const r = decodeEarlyData(arena, "++8=").?;
    try std.testing.expectEqualSlices(u8, &.{ 0xFB, 0xEF }, r);
    try std.testing.expect(decodeEarlyData(arena, "!!") == null); // 非法 → 忽略
    try std.testing.expect(decodeEarlyData(arena, "") == null);
}

test "tokenContains" {
    try std.testing.expect(tokenContains("keep-alive, Upgrade", "upgrade"));
    try std.testing.expect(tokenContains("UPGRADE", "upgrade"));
    try std.testing.expect(tokenContains("Upgrade", "websocket") == false);
    try std.testing.expect(tokenContains("", "upgrade") == false);
}
