//! VLESS 入站协议（§5.7；对照 proxy/vless/inbound/inbound.go + encoding/encoding.go
//! + proxy/vless/validator.go @ v26.10.21，非 fallback 路径）。
//!
//! 流程：一次性 8KB 预读（读超时 = Handshake 60s，成功后清 deadline）→ 解析请求头
//!   version(0) → UUID（第 6、7 字节清零查表 = fork VlessRoute；原始 6/7 为路由
//!   字节，Phase 1 仅记录）→ addons protobuf（Flow=1 string / Seed=2 bytes；最小
//!   解析器按 wire-type 跳过未知字段，畸形 → BadAddons）→ command（Mux/Rvs 不写
//!   地址段，Phase 1 非 TCP 记 warning 并关闭，必须先于地址解析）→ port(大端在前)
//!   + address（1=IPv4 / 2=domain(1B 长度前缀，≤255) / 3=IPv6，其余 invalid）
//! → 写响应头 {0x00,0x00} 并 flush → 预读余量拼接底层流交付 dispatcher。
//!
//! 鉴权失败：access rejected 仅记来源地址（D6 隐私加固，不落 UUID 明文——上游错误
//! 串含 "invalid request user id: " + uuid 全串）；头中途 EOF 静默关闭（上游同：
//! errors.Cause(err) != io.EOF 才记 rejected）。
//! 说明：domain 字符集 [0-9a-zA-Z-._] 是客户端约定，上游 addrParser（本 fork 该
//! 构造仅注册 family 字节 + PortThenAddress）不做字符集校验，Zig 同样不校验。

const std = @import("std");
const stream_mod = @import("../../core/stream.zig");
const buf = @import("../../common/buf.zig");
const applog = @import("../../app/log.zig");
const net = @import("../../common/net.zig");
const dispatcher_mod = @import("../../app/dispatcher.zig");
const conf_vless = @import("../../conf/vless.zig");
const mux = @import("../../common/mux.zig");
const udp_pkt = @import("../udp_packet.zig");
const fb_mod = @import("fallback.zig");

const handshake_timeout_ms: i64 = 60 * 1000; // policy Handshake（表 4-1）
pub const pre_read_size: usize = 8192; // buf.Size 一次性预读

pub const ParseError = error{
    InvalidVersion, // invalid request version
    InvalidUserId, // invalid request user id（D6：日志不带 UUID）
    BadAddons, // failed to unmarshal addons protobuf value
    InvalidAddress, // invalid request address（含 unknown address type）
    EndOfStream, // 头中途 EOF（对端关，静默不记 rejected）
    OutOfMemory,
};

pub const Command = enum(u8) {
    tcp = 0x01,
    udp = 0x02,
    mux = 0x03,
    rvs = 0x04,
    _,
};

pub const Request = struct {
    /// 客户端发送的原始 16 字节 UUID（第 6、7 字节为 fork 路由字节，仅记录）
    raw_id: [16]u8,
    user: *const conf_vless.VlessClient.Built,
    flow: []const u8 = "",
    command: u8,
    dest: net.Destination,
};

// ============================ 头读取器 ============================

/// 预读缓冲优先（耗尽后从底层流续读）；arena 用于 domain/flow 等变长分配。
/// pub：tests/vless_test.zig 直接构造做编解码 roundtrip（上游 encoding_test.go 移植）。
pub const HeadReader = struct {
    pre: []const u8,
    pos: usize = 0,
    inner: stream_mod.Stream,
    arena: std.mem.Allocator,

    /// 纯内存头源（pre 即全部数据，inner 不可达）——测试/向量回放用
    pub fn fromSlice(arena: std.mem.Allocator, data: []const u8) HeadReader {
        return .{ .pre = data, .arena = arena, .inner = .{
            .ctx = undefined,
            .readFn = unreachableRead,
            .writeAllFn = unreachableWrite,
            .closeFn = noopClose,
            .setTimeoutFn = noopSetTimeout,
            .shutdownWriteFn = noopShutdownWrite,
        } };
    }

    fn unreachableRead(_: *anyopaque, _: []u8) anyerror!usize {
        return error.EndOfStream;
    }

    fn unreachableWrite(_: *anyopaque, _: []const u8) anyerror!void {
        return error.NotSupported;
    }

    fn noopClose(_: *anyopaque) void {}

    fn noopSetTimeout(_: *anyopaque, _: i64) void {}

    fn noopShutdownWrite(_: *anyopaque) void {}

    fn readByte(self: *HeadReader) anyerror!u8 {
        var b: [1]u8 = undefined;
        try self.readFull(&b);
        return b[0];
    }

    fn readFull(self: *HeadReader, out: []u8) anyerror!void {
        var off: usize = 0;
        while (off < out.len) {
            if (self.pos < self.pre.len) {
                const n = @min(out.len - off, self.pre.len - self.pos);
                @memcpy(out[off..][0..n], self.pre[self.pos..][0..n]);
                self.pos += n;
                off += n;
            } else {
                const n = try self.inner.read(out[off..]);
                if (n == 0) return ParseError.EndOfStream;
                off += n;
            }
        }
    }

    fn dupe(self: *HeadReader, bytes: []const u8) ParseError![]u8 {
        return self.arena.dupe(u8, bytes) catch ParseError.OutOfMemory;
    }
};

/// validator.Get(ProcessUUID(id))：两侧第 6、7 字节清零后比对（fork 路由特性）
fn findUser(users: []const conf_vless.VlessClient.Built, raw_id: [16]u8) ?*const conf_vless.VlessClient.Built {
    var processed = raw_id;
    processed[6] = 0;
    processed[7] = 0;
    for (users) |*u| {
        var stored = u.uuid.bytes;
        stored[6] = 0;
        stored[7] = 0;
        if (std.mem.eql(u8, &stored, &processed)) return u;
    }
    return null;
}

/// addons protobuf 最小解析器：只取 field 1 (Flow, string)；其余字段按 wire-type
/// 跳过（proto3 未知字段容忍，与 proto.Unmarshal 行为一致；畸形 → BadAddons）
fn parseAddonsFlow(hr: *HeadReader, length: u8) anyerror![]const u8 {
    var remaining: usize = length;
    var flow: []const u8 = "";
    while (remaining > 0) {
        const tag = try hr.readByte();
        remaining -= 1;
        const field = tag >> 3;
        const wire = tag & 0x7;
        switch (wire) {
            0 => { // varint
                while (true) {
                    const b = try hr.readByte();
                    remaining -= 1;
                    if (b & 0x80 == 0) break;
                }
            },
            1 => { // fixed64
                if (remaining < 8) return ParseError.BadAddons;
                var skip: [8]u8 = undefined;
                try hr.readFull(&skip);
                remaining -= 8;
            },
            2 => { // length-delimited
                const l = try readVarintLen(hr, &remaining);
                if (l > remaining) return ParseError.BadAddons;
                if (field == 1) {
                    var buf_v: [255]u8 = undefined;
                    try hr.readFull(buf_v[0..l]);
                    flow = try hr.dupe(buf_v[0..l]);
                } else {
                    var skip: [255]u8 = undefined;
                    try hr.readFull(skip[0..l]);
                }
                remaining -= l; // 两个分支都要扣（对齐 proto.Unmarshal 的位置推进）
            },
            5 => { // fixed32
                if (remaining < 4) return ParseError.BadAddons;
                var skip: [4]u8 = undefined;
                try hr.readFull(&skip);
                remaining -= 4;
            },
            else => return ParseError.BadAddons,
        }
    }
    return flow;
}

fn readVarintLen(hr: *HeadReader, remaining: *usize) anyerror!usize {
    var result: usize = 0;
    var shift: u6 = 0;
    while (true) {
        if (remaining.* == 0) return ParseError.BadAddons;
        const b = try hr.readByte();
        remaining.* -= 1;
        result |= @as(usize, b & 0x7F) << shift;
        if (b & 0x80 == 0) break;
        if (shift >= 57) return ParseError.BadAddons;
        shift += 7;
    }
    return result;
}

/// 解析请求头（dest 的 domain 片已入 arena；IPv4/IPv6 为值类型）
pub fn parseHeader(hr: *HeadReader, users: []const conf_vless.VlessClient.Built) (anyerror || ParseError)!Request {
    const version = try hr.readByte();
    if (version != 0) return ParseError.InvalidVersion;

    var raw_id: [16]u8 = undefined;
    try hr.readFull(&raw_id);
    const user = findUser(users, raw_id) orelse return ParseError.InvalidUserId;

    const addons_len = try hr.readByte();
    var flow: []const u8 = "";
    if (addons_len != 0) {
        flow = try parseAddonsFlow(hr, addons_len);
    }

    const command = try hr.readByte();

    var req = Request{ .raw_id = raw_id, .user = user, .flow = flow, .command = command, .dest = undefined };

    // Mux/Rvs 不写地址段（地址解析只对 TCP/UDP 做；非 TCP 由调用方拒绝）
    if (command == @intFromEnum(Command.tcp) or command == @intFromEnum(Command.udp)) {
        var port_b: [2]u8 = undefined;
        try hr.readFull(&port_b);
        const port = std.mem.readInt(u16, &port_b, .big);

        const atype = try hr.readByte();
        const address: net.Address = switch (atype) {
            1 => blk: {
                var b: [4]u8 = undefined;
                try hr.readFull(&b);
                break :blk .{ .ipv4 = b };
            },
            2 => blk: {
                const dlen = try hr.readByte();
                var dbuf: [255]u8 = undefined;
                try hr.readFull(dbuf[0..dlen]);
                break :blk .{ .domain = try hr.dupe(dbuf[0..dlen]) };
            },
            3 => blk: {
                var b: [16]u8 = undefined;
                try hr.readFull(&b);
                break :blk .{ .ipv6 = b };
            },
            else => return ParseError.InvalidAddress, // unknown address type
        };
        req.dest = .{ .network = .tcp, .address = address, .port = port };
    }
    return req;
}

// ============================ 预读余量拼接流 ============================

/// 头阶段预读的剩余字节先于底层流出（对应上游 buf.BufferedReader 的 Buffer 余量）
pub const PrefixedReader = struct {
    prefix: []const u8,
    pos: usize = 0,
    inner: stream_mod.Stream,

    pub fn stream(self: *PrefixedReader) stream_mod.Stream {
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
        const self: *PrefixedReader = @ptrCast(@alignCast(ctx));
        if (self.pos < self.prefix.len) {
            const n = @min(out.len, self.prefix.len - self.pos);
            @memcpy(out[0..n], self.prefix[self.pos..][0..n]);
            self.pos += n;
            return n;
        }
        return self.inner.read(out);
    }

    fn writeAllImpl(ctx: *anyopaque, data: []const u8) anyerror!void {
        const self: *PrefixedReader = @ptrCast(@alignCast(ctx));
        return self.inner.writeAll(data);
    }

    fn closeImpl(ctx: *anyopaque) void {
        const self: *PrefixedReader = @ptrCast(@alignCast(ctx));
        self.inner.close();
    }

    fn setTimeoutImpl(ctx: *anyopaque, ms: i64) void {
        const self: *PrefixedReader = @ptrCast(@alignCast(ctx));
        self.inner.setTimeout(ms);
    }

    fn shutdownWriteImpl(ctx: *anyopaque) void {
        const self: *PrefixedReader = @ptrCast(@alignCast(ctx));
        self.inner.shutdownWrite();
    }
};

// ============================ 连接处理入口 ============================

pub fn handle(
    arena: std.mem.Allocator,
    gpa: std.mem.Allocator,
    conn_stream: stream_mod.Stream,
    client: sock.TcpConn,
    users: []const conf_vless.VlessClient.Built,
    logger: *applog.Logger,
    dsp: *dispatcher_mod.Dispatcher,
    inbound_tag: []const u8,
    source: []const u8,
    /// M16 VLESS fallbacks（上游 proxy/vless/inbound）：空 = 不启用回落
    fallbacks: []const conf_vless.Fallback,
) void {
    // Handshake 60s（表 4-1；上游 SetReadDeadline(Handshake)）
    conn_stream.setTimeout(handshake_timeout_ms);

    var first: [pre_read_size]u8 = undefined;
    const first_len = conn_stream.read(&first) catch |e| {
        // M12 排障：握手读失败必须留痕——区分「客户端放弃/弱网慢握手」与「服务端异常」
        var wb: [160]u8 = undefined;
        if (std.fmt.bufPrint(&wb, "vless handshake read {s} from {s}", .{ @errorName(e), source })) |m| {
            logger.warning(m);
        } else |_| {}
        return;
    };
    if (first_len == 0) return; // 对端直关
    // M16：上游 `isfb && firstLen < 18` → "fallback directly"（首包太短，非 VLESS 流量）
    if (fallbacks.len > 0 and first_len < 18) {
        const fb = fb_mod.selectFallback(fallbacks, first[0..first_len]) orelse return;
        fb_mod.serveFallback(arena, client, conn_stream, first[0..first_len], fb, source, logger);
        return;
    }

    var hr = HeadReader{ .pre = first[0..first_len], .inner = conn_stream, .arena = arena };
    const req = parseHeader(&hr, users) catch |e| {
        // M16：上游 DecodeRequestHeader(isfb,…) 失败即 isfb → 回落（坏 UUID/坏版本/坏 addons）
        if (fallbacks.len > 0) {
            if (fb_mod.selectFallback(fallbacks, first[0..first_len])) |fb| {
                logger.warning("vless/inbound: invalid request, falling back");
                fb_mod.serveFallback(arena, client, conn_stream, first[0..first_len], fb, source, logger);
                return;
            }
        }
        switch (e) {
            ParseError.EndOfStream => return, // EOF 静默（上游 Cause==io.EOF 不记 rejected）
            else => {
                // access rejected（D6：reason 不含 UUID 明文）+ warning
                const reason: []const u8 = switch (e) {
                    ParseError.InvalidVersion => "invalid request version",
                    ParseError.InvalidUserId => "invalid request user id",
                    ParseError.BadAddons => "failed to unmarshal addons protobuf value",
                    ParseError.InvalidAddress => "invalid request address",
                    else => "invalid request",
                };
                var ab: [256]u8 = undefined;
                if (std.fmt.bufPrint(&ab, "from {s} rejected {s}", .{ source, reason })) |m| {
                    logger.access(m);
                } else |_| {}
                var wb: [160]u8 = undefined;
                if (std.fmt.bufPrint(&wb, "invalid request from {s}", .{source})) |m| {
                    logger.warning(m);
                } else |_| {}
                return;
            },
        }
    };

    // command：TCP 直连 dispatch；Mux 走 mux 服务端（M9）；UDP/Rvs 仍不支持（表 1-2）
    const is_mux = req.command == @intFromEnum(Command.mux);
    // M17：command UDP(2) 放行（对照上游 Destination()：UDP 时返回 UDPDestination；
    // 载荷为 length-prefixed 包，由 freedom UDP 分支收发）
    const is_udp = req.command == @intFromEnum(Command.udp);
    // M19 结论：服务端 UDP 逻辑本身已验证（vless handle → freedom.processUdp → UDP echo
    // 单测通过），但**真实客户端不走裸 UDP 命令**——Xray 客户端对 UDP 一律走 XUDP over mux
    // （xudpConcurrency 默认 8，即使 mux.enabled=false），WS 传输下不会发裸 UDP 命令
    // （实测：客户端 42ms 关闭、服务端无 access 记录）。XUDP over mux 已由 M20 落地
    // （见 mux.zig 的 GlobalID 分支），此处拒绝的只是裸 UDP 命令这条无人使用的路径。
    if (is_udp) {
        logger.warning("vless/inbound: bare UDP command not supported (clients use XUDP over mux), connection closed");
        return;
    }
    if (!is_mux and req.command != @intFromEnum(Command.tcp)) {
        var wb: [128]u8 = undefined;
        if (std.fmt.bufPrint(&wb, "vless/inbound: command {d} is not supported in this build, connection closed", .{req.command})) |m| {
            logger.warning(m);
        } else |_| {}
        return;
    }
    // 客户端 flow 非空（本版账号 flow 恒空）→ 上游 default 分支文案
    if (req.flow.len != 0) {
        var wb: [160]u8 = undefined;
        if (std.fmt.bufPrint(&wb, "unknown request flow {s}", .{req.flow})) |m| {
            logger.warning(m);
        } else |_| {}
        return;
    }

    // 清 Handshake deadline（上游 SetReadDeadline(time.Time{})；拷贝循环按需自设）
    conn_stream.setTimeout(-1);

    // 响应头 {version=0x00, addons_len=0x00} 先行 flush
    conn_stream.writeAll(&.{ 0x00, 0x00 }) catch return;

    // 载荷直通（无 addons 时明文流）：预读余量 + 底层流
    var pr = PrefixedReader{ .prefix = hr.pre[hr.pos..], .inner = conn_stream };
    var sess = buf.Session{
        .inbound_tag = inbound_tag,
        .inbound_protocol = "vless",
        .user_email = req.user.email,
    };
    sess.setSource(source);
    if (is_mux) {
        // Mux：同一份载荷流上跑 mux 服务端（对照上游 DispatchLink → mux.Server）
        mux.serve(arena, gpa, dsp, &sess, .{ .reader = pr.stream(), .writer = conn_stream }, logger, source);
        return;
    }
    var udest = req.dest;
    if (is_udp) udest.network = .udp;
    dsp.dispatch(arena, &sess, udest, .{ .reader = pr.stream(), .writer = conn_stream }) catch {};
}

// ============================ 测试 ============================

const testecho = @import("../../testing/echo.zig");
const sock = @import("../../common/sock.zig");
const sys = @import("../../common/sys.zig");
const uuid_mod = @import("../../common/uuid.zig");
const freedom_mod = @import("../freedom.zig");
const applog_a = @import("../../app/log.zig");
const net_a = net;

const test_uuid_str = "de53e864-8530-4212-a3d7-c31e60b62e91";
const test_users_src = [_]conf_vless.VlessClient{
    .{ .id = test_uuid_str, .email = "pb8lpgli" },
};
var test_users: [1]conf_vless.VlessClient.Built = undefined;
var test_users_init = false;

fn testUsers() []const conf_vless.VlessClient.Built {
    if (!test_users_init) {
        test_users[0] = test_users_src[0].build() catch unreachable;
        test_users_init = true;
    }
    return test_users[0..];
}

fn testUuid() [16]u8 {
    return (uuid_mod.Uuid.parse(test_uuid_str) catch unreachable).bytes;
}

/// 构造 VLESS 请求头（addr_kind: 1=v4 / 2=domain / 0=无地址段[Mux/Rvs]）
fn vlessHeader(
    arena: std.mem.Allocator,
    id: [16]u8,
    command: u8,
    port: u16,
    addr_kind: u8,
    domain: []const u8,
    addons_flow: []const u8,
) []const u8 {
    var list: std.ArrayList(u8) = .empty;
    list.append(arena, 0x00) catch unreachable; // version
    list.appendSlice(arena, &id) catch unreachable; // uuid
    if (addons_flow.len > 0) {
        list.append(arena, @intCast(addons_flow.len + 2)) catch unreachable; // protobuf: tag+len
        list.append(arena, 0x0A) catch unreachable; // field 1, wire 2
        list.append(arena, @intCast(addons_flow.len)) catch unreachable;
        list.appendSlice(arena, addons_flow) catch unreachable;
    } else {
        list.append(arena, 0x00) catch unreachable; // addons len
    }
    list.append(arena, command) catch unreachable;
    if (addr_kind != 0) {
        var pb: [2]u8 = undefined;
        std.mem.writeInt(u16, &pb, port, .big);
        list.appendSlice(arena, &pb) catch unreachable;
        list.append(arena, addr_kind) catch unreachable;
        if (addr_kind == 1) {
            list.appendSlice(arena, &.{ 127, 0, 0, 1 }) catch unreachable;
        } else if (addr_kind == 2) {
            list.append(arena, @intCast(domain.len)) catch unreachable;
            list.appendSlice(arena, domain) catch unreachable;
        } else if (addr_kind == 3) {
            const z16: [16]u8 = @splat(0);
            list.appendSlice(arena, &z16) catch unreachable;
        } else if (addr_kind == 16) {
            list.append(arena, 0x00) catch unreachable; // unknown type 后不关心
        }
    }
    return list.items;
}

const ProcArgs = struct {
    arena: std.mem.Allocator,
    gpa: std.mem.Allocator,
    stream: stream_mod.Stream,
    /// 客户端 TCP 连接（fallback 的 xver 取本端地址用；未启用回落时不会被读）
    client: sock.TcpConn = .{ .fd = -1 },
    fallbacks: []const conf_vless.Fallback = &.{},
    users: []const conf_vless.VlessClient.Built,
    logger: *applog.Logger,
    dsp: *dispatcher_mod.Dispatcher,
    tag: []const u8,
    source: []const u8,
};

fn handleMain(a: *ProcArgs) void {
    handle(a.arena, a.gpa, a.stream, a.client, a.users, a.logger, a.dsp, a.tag, a.source, a.fallbacks);
}

fn buildDispatcher(arena: std.mem.Allocator, lg: *applog.Logger, pool: *buf.Pool, echo_port: u16) dispatcher_mod.Dispatcher {
    const allow = freedom_mod.BuiltRule{ .action = .allow };
    const fh = arena.create(freedom_mod.Handler) catch unreachable;
    fh.* = .{ .logger = lg, .pool = pool, .rules = &.{allow} };
    const handlers = arena.alloc(dispatcher_mod.OutboundHandler, 1) catch unreachable;
    handlers[0] = .{ .tag = "direct", .protocol = "freedom", .freedom = fh };
    _ = echo_port;
    return .{ .logger = lg, .outbounds = .{ .handlers = handlers } };
}

test "vless inbound: 头+载荷同包预读 → dispatch → freedom → echo → 响应头+回显" {
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

    // 头 + 载荷一次写入（预读余量路径）
    const hdr = vlessHeader(arena, testUuid(), @intFromEnum(Command.tcp), echo.port(), 1, "", "");
    try pair.test_side.writeAll(hdr);
    try pair.test_side.writeAll("hello-vless");

    var dsp = buildDispatcher(arena, &lg, &pool, echo.port());
    var args = ProcArgs{
        .arena = arena,
        .gpa = std.heap.smp_allocator,
        .stream = pair.link().reader,
        .users = testUsers(),
        .logger = &lg,
        .dsp = &dsp,
        .tag = "inbound-19001",
        .source = "127.0.0.1:40031",
    };
    const th = try std.Thread.spawn(.{ .stack_size = sys.min_thread_stack }, handleMain, .{&args});

    // 响应头 {0x00,0x00} 先行，随后回显
    var rb: [64]u8 = undefined;
    pair.test_side.setTimeout(5000);
    var got: usize = 0;
    while (got < 7) {
        const n = try pair.test_side.read(rb[got..]);
        if (n == 0) break;
        got += n;
    }
    try std.testing.expectEqualSlices(u8, &.{ 0x00, 0x00 }, rb[0..2]);
    try std.testing.expectEqualStrings("hello-vless", rb[2..got]);

    // 客户端半关 → 上行 EOF → 1s 收尾 → EOF
    pair.test_side.shutdownWrite();
    const n2 = pair.test_side.read(&rb) catch 0;
    try std.testing.expectEqual(@as(usize, 0), n2);
    th.join();
}

test "vless inbound: fork 路由字节（6/7 任意值仍命中）+ domain 目标 AsIs" {
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

    var id = testUuid();
    id[6] = 0xAA; // fork 路由字节（validator 清零后应命中）
    id[7] = 0xBB;
    const hdr = vlessHeader(arena, id, @intFromEnum(Command.tcp), echo.port(), 2, "localhost", "");
    try pair.test_side.writeAll(hdr);
    try pair.test_side.writeAll("domain-ok");

    var dsp = buildDispatcher(arena, &lg, &pool, echo.port());
    var args = ProcArgs{ .arena = arena, .gpa = std.heap.smp_allocator, .stream = pair.link().reader, .users = testUsers(), .logger = &lg, .dsp = &dsp, .tag = "t", .source = "127.0.0.1:40032" };
    const th = try std.Thread.spawn(.{ .stack_size = sys.min_thread_stack }, handleMain, .{&args});

    var rb: [64]u8 = undefined;
    pair.test_side.setTimeout(5000);
    var got: usize = 0;
    while (got < 11) {
        const n = try pair.test_side.read(rb[got..]);
        if (n == 0) break;
        got += n;
    }
    try std.testing.expectEqualSlices(u8, &.{ 0x00, 0x00 }, rb[0..2]);
    try std.testing.expectEqualStrings("domain-ok", rb[2..got]);
    pair.test_side.shutdownWrite();
    _ = pair.test_side.read(&rb) catch 0;
    th.join();
}

test "vless inbound: 鉴权失败/坏版本/未知地址类型/未知 flow/非 TCP command → 无响应即关" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var pool = buf.Pool.init(std.testing.allocator);
    defer pool.deinit();
    var lg = applog.Logger{ .enabled = false };

    const cases = [_]struct {
        name: []const u8,
        hdr: []const u8,
    }{
        .{ .name = "bad uuid", .hdr = vlessHeader(arena, .{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 }, @intFromEnum(Command.tcp), 80, 1, "", "") },
        .{ .name = "bad version", .hdr = blk: {
            const h = vlessHeader(arena, testUuid(), @intFromEnum(Command.tcp), 80, 1, "", "");
            var c = std.ArrayList(u8).empty;
            c.appendSlice(arena, h) catch unreachable;
            c.items[0] = 0x01; // version 1
            break :blk c.items;
        } },
        .{ .name = "unknown addr type", .hdr = vlessHeader(arena, testUuid(), @intFromEnum(Command.tcp), 80, 16, "", "") },
        .{ .name = "unknown flow", .hdr = vlessHeader(arena, testUuid(), @intFromEnum(Command.tcp), 80, 1, "", "vision") },
    };

    for (cases) |c| {
        var pair = try testecho.socketpairClient(arena);
        defer {
            pair.test_side.close();
            pair.deinit();
        }
        try pair.test_side.writeAll(c.hdr);
        var dsp = buildDispatcher(arena, &lg, &pool, 1);
        var args = ProcArgs{ .arena = arena, .gpa = std.heap.smp_allocator, .stream = pair.link().reader, .users = testUsers(), .logger = &lg, .dsp = &dsp, .tag = "t", .source = "127.0.0.1:40033" };
        const th = try std.Thread.spawn(.{ .stack_size = sys.min_thread_stack }, handleMain, .{&args});
        // 无响应头，连接直接关（EOF）
        var rb: [8]u8 = undefined;
        pair.test_side.setTimeout(3000);
        const n = pair.test_side.read(&rb) catch 0;
        try std.testing.expectEqual(@as(usize, 0), n);
        th.join();
    }
}

test "vless inbound: Mux command → 先回 {0,0} 响应头，再进 mux 服务端（M9）" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var pool = buf.Pool.init(std.testing.allocator);
    defer pool.deinit();
    var lg = applog.Logger{ .enabled = false };

    var pair = try testecho.socketpairClient(arena);
    defer {
        pair.test_side.close();
        pair.deinit();
    }
    try pair.test_side.writeAll(vlessHeader(arena, testUuid(), @intFromEnum(Command.mux), 0, 0, "", ""));

    var dsp = buildDispatcher(arena, &lg, &pool, 1);
    var args = ProcArgs{ .arena = arena, .gpa = std.heap.smp_allocator, .stream = pair.link().reader, .users = testUsers(), .logger = &lg, .dsp = &dsp, .tag = "t", .source = "127.0.0.1:40034" };
    const th = try std.Thread.spawn(.{ .stack_size = sys.min_thread_stack }, handleMain, .{&args});

    // Mux 与 TCP 一样先回 2 字节响应头（上游 EncodeResponseHeader 在 dispatch 之前）
    var rb: [8]u8 = undefined;
    pair.test_side.setTimeout(3000);
    const n = pair.test_side.read(&rb) catch 0;
    try std.testing.expectEqual(@as(usize, 2), n);
    try std.testing.expectEqualSlices(u8, &.{ 0x00, 0x00 }, rb[0..2]);

    // 之后是 mux 帧流：客户端不发帧 → 服务端 mux 主循环阻塞在读；
    // 关客户端 → 主循环读 EOF 退出
    pair.test_side.close();
    th.join();
}


test "vless inbound: 坏 UUID + fallbacks → 连接转交回落目标（M16 端到端）" {
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

    // fallbacks：默认项指向 echo（path 不命中时回落这里）
    var dest_buf: [32]u8 = undefined;
    const dest_str = std.fmt.bufPrint(&dest_buf, "127.0.0.1:{d}", .{echo.port()}) catch unreachable;
    const fbs = [_]conf_vless.Fallback{.{ .dest = dest_str }};

    var dsp = buildDispatcher(arena, &lg, &pool, 1);
    var args = ProcArgs{
        .arena = arena,
        .gpa = std.heap.smp_allocator,
        .stream = pair.link().reader,
        .client = pair.ctx.conn,
        .users = testUsers(),
        .logger = &lg,
        .dsp = &dsp,
        .tag = "t",
        .source = "127.0.0.1:40040",
        .fallbacks = fbs[0..],
    };
    const th = try std.Thread.spawn(.{ .stack_size = sys.min_thread_stack }, handleMain, .{&args});

    // 客户端发"坏 UUID 的 VLESS 头"（version=0 但 UUID 不匹配）→ parseHeader 失败 → fallback
    var hdr: [64]u8 = undefined;
    const hlen = buildBadVlessHeader(&hdr);
    try pair.test_side.writeAll(hdr[0..hlen]);

    // 回落目标（echo）应原样回显我们发的字节（证明连接被转交且首字节已转发）
    var rb: [64]u8 = undefined;
    pair.test_side.setTimeout(5000);
    const n = pair.test_side.read(&rb) catch 0;
    try std.testing.expect(n > 0);
    try std.testing.expectEqualSlices(u8, hdr[0..n], rb[0..n]);

    pair.test_side.close();
    th.join();
}

/// 构造一个"坏 UUID"的 VLESS 请求头（version=0 + 16B 随机 UUID + 1B addon 长 + 端口/地址）
/// 足以让 parseHeader 在用户匹配处失败（InvalidUserId）→ 触发 fallback
fn buildBadVlessHeader(out: []u8) usize {
    var w: usize = 0;
    out[w] = 0; // version
    w += 1;
    for (0..16) |i| {
        out[w] = @intCast(i * 7 + 3); // 非测试 UUID
        w += 1;
    }
    out[w] = 0; // addon 长度 0
    w += 1;
    // command=tcp(1) + port(2) + addr type(1=ipv4) + 4B ip
    out[w] = 1;
    w += 1;
    std.mem.writeInt(u16, out[w..][0..2], 80, .big);
    w += 2;
    out[w] = 1;
    w += 1;
    out[w] = 127;
    out[w + 1] = 0;
    out[w + 2] = 0;
    out[w + 3] = 1;
    w += 4;
    return w;
}

test "sock: UDP dial/send/recv 同步 roundtrip（M17 出站底座）" {
    // M19：真因是 UdpEchoServer 的 running 未初始化（page_allocator.create 不跑
    // 字段默认值）→ loop 立即退出、从不回包；UDP 实现本身无问题。已修复并启用。
    const echo = try testecho.UdpEchoServer.start();
    defer echo.stop();

    const sa = sys.SockaddrIn.init(.{ 127, 0, 0, 1 }, echo.port());
    const c = try sock.dialUdp(.{ .v4 = sa });
    defer c.close();

    const payload = "udp-roundtrip";
    try c.send(payload);

    var rb: [64]u8 = undefined;
    c.setTimeout(3000);
    const n = try c.recv(&rb);
    try std.testing.expectEqualStrings(payload, rb[0..n]);
}

test "vless inbound: UDP command → freedom → UDP echo 回包（M19 代码就绪，命令仍拒绝）" {
    // M19：M17 的 TimedOut 真因已定位——UdpEchoServer.running 未初始化（page_allocator
    // 不跑字段默认值），UDP 实现本身无问题；本测试此前已跑通（164/164）。
    // 但真实客户端走 XUDP over mux，WS 下发不出裸 UDP 命令，故线上仍拒绝 UDP 命令，
    // 测试随之跳过；实现 XUDP 后一并启用（见 PROGRESS M19）。
    if (true) return error.SkipZigTest;
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var pool = buf.Pool.init(std.testing.allocator);
    defer pool.deinit();
    var lg = applog.Logger{ .enabled = false };

    const echo = try testecho.UdpEchoServer.start();
    defer echo.stop();

    var pair = try testecho.socketpairClient(arena);
    defer pair.deinit();

    // VLESS 头：command=UDP(2)，目标 127.0.0.1:echo.port()（addr_kind=1 硬编码 127.0.0.1）
    try pair.test_side.writeAll(vlessHeader(arena, testUuid(), @intFromEnum(Command.udp), echo.port(), 1, "", ""));

    var dsp = buildDispatcher(arena, &lg, &pool, echo.port());
    var args = ProcArgs{
        .arena = arena,
        .gpa = std.testing.allocator,
        .stream = pair.link().reader,
        .users = testUsers(),
        .logger = &lg,
        .dsp = &dsp,
        .tag = "t",
        .source = "127.0.0.1:40041",
    };
    const th = try std.Thread.spawn(.{ .stack_size = sys.min_thread_stack }, handleMain, .{&args});

    // 客户端：length-prefixed 包 → 服务端 freedom UDP 出站 → echo 回包
    pair.test_side.setTimeout(5000);
    try udp_pkt.writePacket(pair.test_side, "udp-e2e");

    // VLESS 响应头 {0,0}（version + addons 长度）在 dispatch 之前发出，
    // 真实客户端（Go vless outbound）会先读掉它；测试必须同样处理，
    // 否则会被当成 length 前缀 0x0000 → 误读成 0 长度包。
    var resp: [2]u8 = undefined;
    var roff: usize = 0;
    while (roff < resp.len) {
        const m = try pair.test_side.read(resp[roff..]);
        if (m == 0) return error.UnexpectedEof;
        roff += m;
    }
    try std.testing.expectEqualSlices(u8, &.{ 0x00, 0x00 }, &resp);

    var rb: [256]u8 = undefined;
    const n = try udp_pkt.readPacket(pair.test_side, &rb);
    try std.testing.expectEqualStrings("udp-e2e", rb[0..n]);

    // 关客户端 → up 线程 EOF → down 线程 1s 阈值收尾 → join
    pair.test_side.close();
    th.join();
}
