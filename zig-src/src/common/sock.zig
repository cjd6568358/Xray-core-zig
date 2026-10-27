//! TCP socket 层（std.os.linux syscall 直用；对照 transport/internet/system_dialer.go、
//! system_listener.go 的可观测行为）。
//! 契约（表 4-1）：
//!   - 监听侧恒设 SO_REUSEPORT；入站监听默认不开 keepalive
//!   - 拨号 16s 超时；失败指数退避重试 5 次（基数 100ms）；成功后设 keepalive（45s/45s）
//!   - 读超时用 SO_RCVTIMEO（每操作刷新 deadline），EINTR 重试

const std = @import("std");
const linux = std.os.linux;
const sys = @import("sys.zig");

pub const E = linux.E;
pub const Fd = linux.fd_t;

pub const SocketError = error{
    WouldBlock, // 超时（SO_RCVTIMEO/SO_SNDTIMEO 到期）
    ConnRefused,
    ConnReset,
    ConnAborted,
    TimedOut,
    AddrInUse,
    NetworkUnreachable,
    Unexpected,
};

fn mapErrno(e: E) SocketError {
    return switch (e) {
        .AGAIN, .TIMEDOUT => SocketError.WouldBlock,
        .CONNREFUSED => SocketError.ConnRefused,
        .CONNRESET => SocketError.ConnReset,
        .CONNABORTED => SocketError.ConnAborted,
        .NETUNREACH, .HOSTUNREACH, .ACCES => SocketError.NetworkUnreachable,
        .ADDRINUSE => SocketError.AddrInUse,
        .INTR => SocketError.Unexpected, // 循环重试层处理，不应透出
        else => SocketError.Unexpected,
    };
}

// ============================ 公共 sockopt ============================

pub fn setReuseAddrPort(fd: Fd) void {
    const one: c_int = 1;
    _ = linux.setsockopt(fd, linux.SOL.SOCKET, linux.SO.REUSEADDR, @ptrCast(&one), @sizeOf(c_int));
    _ = linux.setsockopt(fd, linux.SOL.SOCKET, linux.SO.REUSEPORT, @ptrCast(&one), @sizeOf(c_int));
}

/// 关闭 Nagle 算法。**对齐 Go 行为**：Go 的 net.TCPConn 在 newTCPConn 里
/// 无条件 setNoDelay(true)，故上游（含 accept 出来的入站连接）全部无 Nagle。
/// M12 实机：此前全实现未设 TCP_NODELAY，地铁高 RTT 下小包被 Nagle 压到
/// ACK 返回才发（数十~数百 ms），表现为"卡顿/丢包"体感明显差于 Go 版。
pub fn setNoDelay(fd: Fd) void {
    const one: c_int = 1;
    _ = linux.setsockopt(fd, linux.IPPROTO.TCP, linux.TCP.NODELAY, @ptrCast(&one), @sizeOf(c_int));
}

/// 上游 freedom 拨号成功后的 Chrome 风格 keepalive：idle 45s / interval 45s
pub fn setKeepalive45(fd: Fd) void {
    const one: c_int = 1;
    _ = linux.setsockopt(fd, linux.SOL.SOCKET, linux.SO.KEEPALIVE, @ptrCast(&one), @sizeOf(c_int));
    const idle: c_int = 45;
    _ = linux.setsockopt(fd, linux.IPPROTO.TCP, linux.TCP.KEEPIDLE, @ptrCast(&idle), @sizeOf(c_int));
    const intvl: c_int = 45;
    _ = linux.setsockopt(fd, linux.IPPROTO.TCP, linux.TCP.KEEPINTVL, @ptrCast(&intvl), @sizeOf(c_int));
}

fn setRcvSndTimeout(fd: Fd, ms: i64) void {
    const tv: linux.timeval = .{ .sec = @intCast(@divFloor(ms, 1000)), .usec = @intCast(@mod(ms, 1000) * 1000) };
    _ = linux.setsockopt(fd, linux.SOL.SOCKET, linux.SO.RCVTIMEO, std.mem.asBytes(&tv), @sizeOf(linux.timeval));
    _ = linux.setsockopt(fd, linux.SOL.SOCKET, linux.SO.SNDTIMEO, std.mem.asBytes(&tv), @sizeOf(linux.timeval));
}

fn clearRcvSndTimeout(fd: Fd) void {
    const tv: linux.timeval = .{ .sec = 0, .usec = 0 };
    _ = linux.setsockopt(fd, linux.SOL.SOCKET, linux.SO.RCVTIMEO, std.mem.asBytes(&tv), @sizeOf(linux.timeval));
    _ = linux.setsockopt(fd, linux.SOL.SOCKET, linux.SO.SNDTIMEO, std.mem.asBytes(&tv), @sizeOf(linux.timeval));
}

// ============================ TCP 连接 ============================

/// UDP 连接（对照上游 internet.Dialer UDP 分支 + net.DialUDP 语义）：
/// connect 后固定对端，send/recv 即可（等价 Go 的 *net.UDPConn Read/Write）
pub const UdpConn = struct {
    fd: Fd,

    pub fn close(self: UdpConn) void {
        _ = linux.close(self.fd);
    }

    pub fn setTimeout(self: UdpConn, ms: i64) void {
        if (ms < 0) {
            clearRcvSndTimeout(self.fd);
        } else {
            setRcvSndTimeout(self.fd, ms);
        }
    }

    /// 发一个 UDP 包（已 connect，无需目的地址）
    pub fn send(self: UdpConn, data: []const u8) SocketError!void {
        const rc = linux.sendto(self.fd, data.ptr, data.len, 0, null, 0);
        if (linux.errno(rc) != .SUCCESS) return SocketError.Unexpected;
    }

    /// 收一个 UDP 包；超时返回 error.TimedOut，0 长度包返回 0
    pub fn recv(self: UdpConn, buf: []u8) SocketError!usize {
        while (true) {
            const n = linux.recvfrom(self.fd, buf.ptr, buf.len, 0, null, null);
            switch (linux.errno(n)) {
                .SUCCESS => return @intCast(n),
                .INTR => continue,
                .AGAIN => return SocketError.TimedOut,
                .CONNRESET => return SocketError.Unexpected, // 上游 ICMP port unreachable
                else => return SocketError.Unexpected,
            }
        }
    }
};

/// 拨一个 UDP "连接"（socket + connect；非阻塞探测略过——UDP connect 立即返回）
pub fn dialUdp(sa: sys.Sockaddr) SocketError!UdpConn {
    const rc = linux.socket(linux.AF.INET, linux.SOCK.DGRAM | linux.SOCK.CLOEXEC, 0);
    switch (linux.errno(rc)) {
        .SUCCESS => {},
        else => return SocketError.Unexpected,
    }
    const fd: Fd = @intCast(rc);
    const crc = linux.connect(fd, @ptrCast(&sa), @sizeOf(sys.SockaddrIn));
    switch (linux.errno(crc)) {
        .SUCCESS => return .{ .fd = fd },
        else => {
            _ = linux.close(fd);
            return SocketError.Unexpected;
        },
    }
}

pub const TcpConn = struct {
    fd: Fd,

    pub fn close(self: TcpConn) void {
        _ = linux.close(self.fd);
    }

    pub fn shutdownWrite(self: TcpConn) void {
        _ = linux.shutdown(self.fd, linux.SHUT.WR);
    }

    /// 双向 shutdown：仅用于拷贝线程出错时唤醒另一条阻塞在 read 上的线程
    /// （Linux 上 shutdown 可靠唤醒阻塞 recv，close 不能）
    pub fn shutdownAll(self: TcpConn) void {
        _ = linux.shutdown(self.fd, linux.SHUT.RDWR);
    }

    /// 对端 v4 端点（getpeername；失败返回 null）。拨号后实际地址复检用
    pub fn peerV4(self: TcpConn) ?struct { addr: [4]u8, port: u16 } {
        var sa: sys.SockaddrIn = undefined;
        var slen: linux.socklen_t = @sizeOf(sys.SockaddrIn);
        const rc = linux.getpeername(self.fd, @ptrCast(&sa), &slen);
        if (linux.errno(rc) != .SUCCESS) return null;
        return .{ .addr = sa.addr, .port = sa.port() };
    }

    /// 读：超时由 setTimeout 预先设置；返回 0 = 对端半关闭
    pub fn read(self: TcpConn, buf: []u8) SocketError!usize {
        while (true) {
            const n = linux.recvfrom(self.fd, buf.ptr, buf.len, 0, null, null);
            switch (linux.errno(n)) {
                .SUCCESS => return n,
                .INTR => continue,
                .AGAIN => return SocketError.WouldBlock,
                .CONNRESET => return SocketError.ConnReset,
                .TIMEDOUT => return SocketError.WouldBlock,
                else => return SocketError.Unexpected,
            }
        }
    }

    /// 全量写（阻塞；EINTR 重试）
    /// writev：一次写出多段（M22）。WS 帧的「头 + 载荷」原本是两次 sendto，
    /// 1MiB = 128 帧 → 256 次 syscall；合并后减半（弱网下 TCP 段更紧凑）。
    /// 部分写/EINTR 都正确续写；段数 >4 或单段时退化。
    pub fn writeAllVec(self: TcpConn, parts: []const []const u8) SocketError!void {
        if (parts.len == 0) return;
        if (parts.len == 1) return self.writeAll(parts[0]);
        if (parts.len > 4) {
            for (parts) |p| try self.writeAll(p);
            return;
        }
        var total: usize = 0;
        for (parts) |p| total += p.len;
        var written: usize = 0;
        while (written < total) {
            var riov: [4]std.posix.iovec_const = undefined;
            var rn: usize = 0;
            var skip = written;
            for (parts) |p| {
                if (skip >= p.len) {
                    skip -= p.len;
                    continue;
                }
                riov[rn] = .{ .base = p.ptr + skip, .len = p.len - skip };
                rn += 1;
                skip = 0;
            }
            if (rn == 0) break;
            const n = linux.writev(self.fd, @ptrCast(&riov[0]), @intCast(rn));
            switch (linux.errno(n)) {
                .SUCCESS => written += n,
                .INTR => continue,
                .AGAIN => return SocketError.WouldBlock,
                .CONNRESET, .PIPE => return SocketError.ConnReset,
                else => return SocketError.Unexpected,
            }
        }
    }

    pub fn writeAll(self: TcpConn, data: []const u8) SocketError!void {
        var off: usize = 0;
        while (off < data.len) {
            const n = linux.sendto(self.fd, data.ptr + off, data.len - off, linux.MSG.NOSIGNAL, null, 0);
            switch (linux.errno(n)) {
                .SUCCESS => off += n,
                .INTR => continue,
                .AGAIN => return SocketError.WouldBlock,
                .CONNRESET, .PIPE => return SocketError.ConnReset,
                else => return SocketError.Unexpected,
            }
        }
    }

    pub fn setTimeout(self: TcpConn, ms: i64) void {
        if (ms < 0) {
            clearRcvSndTimeout(self.fd);
        } else {
            setRcvSndTimeout(self.fd, ms);
        }
    }

    pub fn peerAddr(self: TcpConn, buf: []u8) usize {
        var sa: sys.SockaddrIn = undefined;
        var slen: linux.socklen_t = @sizeOf(sys.SockaddrIn);
        const rc = linux.getpeername(self.fd, @ptrCast(&sa), &slen);
        if (linux.errno(rc) != .SUCCESS) return 0;
        return formatV4(sa, buf);
    }

    pub fn localAddr(self: TcpConn, buf: []u8) usize {
        var sa: sys.SockaddrIn = undefined;
        var slen: linux.socklen_t = @sizeOf(sys.SockaddrIn);
        const rc = linux.getsockname(self.fd, @ptrCast(&sa), &slen);
        if (linux.errno(rc) != .SUCCESS) return 0;
        return formatV4(sa, buf);
    }
};

/// 阻塞 connect + SO_SNDTIMEO 非阻塞路径的混合：非阻塞 connect + poll 等待
pub fn dialTcp(sa: sys.Sockaddr, timeout_ms: i64) SocketError!TcpConn {
    const rc = linux.socket(linux.AF.INET, linux.SOCK.STREAM | linux.SOCK.CLOEXEC, 0);
    switch (linux.errno(rc)) {
        .SUCCESS => {},
        else => return SocketError.Unexpected,
    }
    const fd: Fd = @intCast(rc);

    // 非阻塞 connect
    const flags = linux.fcntl(fd, linux.F.GETFL, 0);
    const nb: u32 = @bitCast(linux.O{ .NONBLOCK = true });
    _ = linux.fcntl(fd, linux.F.SETFL, flags | @as(usize, nb));
    const crc = linux.connect(fd, @ptrCast(&sa), @sizeOf(sys.SockaddrIn));
    switch (linux.errno(crc)) {
        .SUCCESS => {},
        .INPROGRESS => {
            // poll 等待可写
            var pfd: [1]linux.pollfd = .{.{ .fd = fd, .events = linux.POLL.OUT, .revents = 0 }};
            const prc = linux.poll(&pfd, 1, @intCast(timeout_ms));
            switch (linux.errno(prc)) {
                .SUCCESS => {
                    if (prc == 0) {
                        _ = linux.close(fd);
                        return SocketError.TimedOut;
                    }
                },
                .INTR => {},
                else => {
                    _ = linux.close(fd);
                    return SocketError.Unexpected;
                },
            }
            // SO_ERROR 检查
            var soerr: c_int = 0;
            var slen: linux.socklen_t = @sizeOf(c_int);
            const grc = linux.getsockopt(fd, linux.SOL.SOCKET, linux.SO.ERROR, @ptrCast(&soerr), &slen);
            if (linux.errno(grc) != .SUCCESS or soerr != 0) {
                _ = linux.close(fd);
                if (soerr == @intFromEnum(E.CONNREFUSED)) return SocketError.ConnRefused;
                return SocketError.Unexpected;
            }
        },
        .INTR => {},
        else => |e| {
            _ = linux.close(fd);
            return mapErrno(e);
        },
    }
    // 恢复阻塞模式
    _ = linux.fcntl(fd, linux.F.SETFL, flags);
    setNoDelay(fd); // 对齐 Go net.TCPConn 默认
    return TcpConn{ .fd = fd };
}

// ============================ TCP 监听 ============================

pub const TcpListener = struct {
    fd: Fd,
    port: u16,

    /// 监听侧恒设 SO_REUSEPORT（上游 system_listener.go:38）
    pub fn bind(octets: [4]u8, port: u16, backlog: u32) SocketError!TcpListener {
        const rc = linux.socket(linux.AF.INET, linux.SOCK.STREAM | linux.SOCK.CLOEXEC, 0);
        switch (linux.errno(rc)) {
            .SUCCESS => {},
            else => return SocketError.Unexpected,
        }
        const fd: Fd = @intCast(rc);
        setReuseAddrPort(fd);
        var sa = sys.SockaddrIn.init(octets, port);
        const brc = linux.bind(fd, @ptrCast(&sa), @sizeOf(sys.SockaddrIn));
        switch (linux.errno(brc)) {
            .SUCCESS => {},
            .ADDRINUSE => {
                _ = linux.close(fd);
                return SocketError.AddrInUse;
            },
            else => {
                _ = linux.close(fd);
                return SocketError.Unexpected;
            },
        }
        const lrc = linux.listen(fd, backlog);
        switch (linux.errno(lrc)) {
            .SUCCESS => {},
            else => {
                _ = linux.close(fd);
                return SocketError.Unexpected;
            },
        }
        return TcpListener{ .fd = fd, .port = port };
    }

    /// accept（阻塞；EINTR 重试）。IPv4 only（本配置 listen 均为 v4）。
    /// 返回 null = 非阻塞模式下的暂无连接（AGAIN）。
    pub fn accept(self: TcpListener) SocketError!?TcpConn {
        while (true) {
            var sa: sys.SockaddrIn = undefined;
            var slen: linux.socklen_t = @sizeOf(sys.SockaddrIn);
            const rc = linux.accept4(self.fd, @ptrCast(&sa), &slen, linux.SOCK.CLOEXEC);
            switch (linux.errno(rc)) {
                .SUCCESS => {
                    const cfd: Fd = @intCast(rc);
                    setNoDelay(cfd); // 对齐 Go net.TCPConn 默认
                    return TcpConn{ .fd = cfd };
                },
                .INTR => continue,
                .AGAIN => return null,
                .CONNABORTED => continue,
                else => return SocketError.Unexpected,
            }
        }
    }

    /// 实际绑定端口（bind port=0 时内核分配；getsockname）
    pub fn actualPort(self: TcpListener) u16 {
        var sa: sys.SockaddrIn = undefined;
        var slen: linux.socklen_t = @sizeOf(sys.SockaddrIn);
        const rc = linux.getsockname(self.fd, @ptrCast(&sa), &slen);
        if (linux.errno(rc) != .SUCCESS) return 0;
        return sa.port();
    }

    pub fn close(self: TcpListener) void {
        _ = linux.close(self.fd);
    }
};

pub fn formatV4(sa: sys.SockaddrIn, buf: []u8) usize {
    const s = std.fmt.bufPrint(buf, "{d}.{d}.{d}.{d}:{d}", .{
        sa.addr[0], sa.addr[1], sa.addr[2], sa.addr[3], sa.port(),
    }) catch return 0;
    return s.len;
}

// ============================ DNS（musl getaddrinfo，AsIs 语义） ============================

/// 域名解析（阻塞；走 musl getaddrinfo，无 NSS 依赖）。仅取首个 A 记录。
pub fn resolveV4(arena: std.mem.Allocator, host: []const u8) ?[4]u8 {
    const c = std.c;
    const hostz = arena.dupeSentinel(u8, host, 0) catch return null;
    var hints: c.addrinfo = std.mem.zeroes(c.addrinfo);
    hints.family = linux.AF.INET;
    hints.socktype = linux.SOCK.STREAM;
    var res: ?*c.addrinfo = null;
    const rc = c.getaddrinfo(hostz.ptr, null, &hints, &res);
    if (@intFromEnum(rc) != 0) return null;
    defer if (res) |r| c.freeaddrinfo(r);
    var cur: ?*c.addrinfo = res;
    while (cur) |ai| : (cur = ai.next) {
        if (ai.addr) |addr| {
            if (addr.family == linux.AF.INET) {
                const sin: *const sys.SockaddrIn = @ptrCast(@alignCast(addr));
                return sin.addr;
            }
        }
    }
    return null;
}

// ============================ M35：进程内 DNS 缓存 ============================
//
// 【动因】光猫 本次观察窗口（8.45h / 2312 连接）实测：域名目标的出站拨号比 IP 字面量
// 目标慢一截，且尾巴很重 ——
//     IP 字面量（无 DNS）：p50=6ms   p90=25ms  p95=32ms
//     域名（需 DNS）    ：p50=18ms  p90=49ms  p95=309ms
// 差出来的部分就是 musl getaddrinfo 的出网往返。更糟的是 `dialWithRetry` 把
// resolveTarget 放在重试循环内部，一条失败连接会重复解析 5 次。
//
// 【TTL 为什么取 60s】缓存期限必须不高于典型 DNS TTL，否则 CDN 换 IP 后会持续
// 连到已下线的地址。60s 足够吃到绝大多数"同域名短时间重复连接"的收益（本窗口
// 274 连接/小时，头部域名几分钟内必然复现），又把陈旧窗口压到一分钟以内。
// 另有兜底：整条拨号彻底失败时 freedom 会调 dnsInvalidate 主动失效该域名。
//
// 【并发要点】getaddrinfo 是阻塞的（实测 p95 达 309ms）。**绝不能在持锁时长阻塞**，
// 否则会把所有需要解析的连接串行化，性能反而比不缓存更差。故采用三段式：
//     ① 加锁查表（线性扫描，微秒级）→ 命中即解锁返回
//     ② **不持锁**做 getaddrinfo
//     ③ 加锁回填
// 代价是缺"缓存击穿保护"（同一域名并发首次解析会各查一次），可接受。

pub const dns_max_entries = 128;
pub const dns_max_host_len = 96;
/// 缓存期限毫秒。置 0 可整体关闭缓存。
pub var dns_cache_ttl_ms: i64 = 60 * 1000;

const DnsEntry = struct {
    host_len: u8 = 0,
    ip: [4]u8 = .{ 0, 0, 0, 0 },
    expire_ms: i64 = 0,
    host: [dns_max_host_len]u8 = undefined,
};

var dns_entries: [dns_max_entries]DnsEntry = std.mem.zeroes([dns_max_entries]DnsEntry);
var dns_len: usize = 0;
var dns_mu: sys.Mutex = .{};

fn dnsLookup(host: []const u8, now: i64) ?[4]u8 {
    if (host.len == 0 or host.len > dns_max_host_len) return null; // 防御：入口若不校验也不致越界
    dns_mu.lock();
    defer dns_mu.unlock();
    for (dns_entries[0..dns_len]) |*e| {
        if (e.host_len != host.len) continue;
        if (!std.mem.eql(u8, e.host[0..e.host_len], host)) continue;
        if (now >= e.expire_ms) return null; // 过期命中按未命中处理
        var out: [4]u8 = undefined;
        @memcpy(&out, &e.ip);
        return out;
    }
    return null;
}

fn dnsInsert(host: []const u8, ip: [4]u8, now: i64) void {
    if (host.len == 0 or host.len > dns_max_host_len) return; // 同上：杜绝 host 缓冲越界
    dns_mu.lock();
    defer dns_mu.unlock();
    // 已存在则刷新（并发重复解析时后者覆盖前者，值等价，无需判先后）
    for (dns_entries[0..dns_len]) |*e| {
        if (e.host_len == host.len and std.mem.eql(u8, e.host[0..e.host_len], host)) {
            @memcpy(&e.ip, &ip);
            e.expire_ms = now + dns_cache_ttl_ms;
            return;
        }
    }
    if (dns_len >= dns_max_entries) return; // 满了：不逐出，直接放弃（保守，避免引入逐出策略的不确定性）
    const e = &dns_entries[dns_len];
    e.host_len = @intCast(host.len);
    @memcpy(e.host[0..host.len], host);
    @memcpy(&e.ip, &ip);
    e.expire_ms = now + dns_cache_ttl_ms;
    dns_len += 1;
}

/// 让某个域名的缓存立即失效（拨号彻底失败时由 freedom 调用，避免 CDN 换 IP 后
/// 一直连已下线地址）。不存在该条目时无操作。
pub fn dnsInvalidate(host: []const u8) void {
    if (host.len == 0 or host.len > dns_max_host_len) return;
    dns_mu.lock();
    defer dns_mu.unlock();
    for (dns_entries[0..dns_len]) |*e| {
        if (e.host_len == host.len and std.mem.eql(u8, e.host[0..e.host_len], host)) {
            e.expire_ms = 0;
            return;
        }
    }
}

/// 带进程内缓存的域名解析。语义与 `resolveV4` 完全一致（仅取首条 A 记录），
/// 差别仅在 TTL 窗口内复用上次结果。TTL<=0 时退化为原 `resolveV4`。
pub fn resolveV4Cached(arena: std.mem.Allocator, host: []const u8) ?[4]u8 {
    if (dns_cache_ttl_ms <= 0 or host.len == 0 or host.len > dns_max_host_len) {
        return resolveV4(arena, host);
    }
    if (dnsLookup(host, sys.nowMonoMs())) |ip| return ip;
    const ip = resolveV4(arena, host) orelse return null; // ② 不持锁的慢调用
    dnsInsert(host, ip, sys.nowMonoMs());
    return ip;
}

// ============================ SIGPIPE ============================

/// 进程启动时屏蔽 SIGPIPE（Go 运行时原生行为；Zig 需自行设置，防写对端关闭即死）
pub fn ignoreSigpipe() void {
    var act: linux.Sigaction = .{
        .handler = .{ .handler = linux.SIG.IGN },
        .mask = linux.sigemptyset(),
        .flags = 0,
    };
    _ = linux.sigaction(.PIPE, &act, null);
}

test "sockaddr format" {
    const sa = sys.SockaddrIn.init(.{ 127, 0, 0, 1 }, 19001);
    var buf: [32]u8 = undefined;
    const n = formatV4(sa, buf[0..]);
    try std.testing.expectEqualStrings("127.0.0.1:19001", buf[0..n]);
}

test "sock: accept/dial 均关闭 Nagle（对齐 Go net.TCPConn 默认）" {
    var l = try TcpListener.bind(.{ 127, 0, 0, 1 }, 0, 16);
    defer l.close();
    const port = l.actualPort();
    const sa = sys.SockaddrIn.init(.{ 127, 0, 0, 1 }, port);

    const c = try dialTcp(.{ .v4 = sa }, 2000);
    defer c.close();
    const s = (try l.accept()) orelse return error.AcceptFailed;
    defer s.close();

    var v: c_int = 0;
    var len: linux.socklen_t = @sizeOf(c_int);
    _ = linux.getsockopt(s.fd, linux.IPPROTO.TCP, linux.TCP.NODELAY, @ptrCast(&v), &len);
    try std.testing.expectEqual(@as(c_int, 1), v); // 入站 accept 侧

    v = 0;
    len = @sizeOf(c_int);
    _ = linux.getsockopt(c.fd, linux.IPPROTO.TCP, linux.TCP.NODELAY, @ptrCast(&v), &len);
    try std.testing.expectEqual(@as(c_int, 1), v); // 出站 dial 侧
}

// ============================ M35：DNS 缓存表 ============================
//
// 刻意合并成**一个**用例：缓存表是模块级全局，Zig 测试执行顺序/并发度不受控，
// 拆成多个用例会互相踩条目。本用例自带首尾复位，故与顺序无关。

test "M35: DNS 缓存表（命中/过期/刷新/失效/容量上界/超长名）" {
    const orig_ttl = dns_cache_ttl_ms;
    defer dns_cache_ttl_ms = orig_ttl; // 不污染其它用例
    dns_cache_ttl_ms = 60 * 1000;

    const reset = struct {
        fn r() void {
            dns_mu.lock();
            defer dns_mu.unlock();
            dns_len = 0;
            for (&dns_entries) |*e| {
                e.host_len = 0;
                e.expire_ms = 0;
            }
        }
    }.r;
    reset();
    defer reset();

    const now: i64 = 1_000_000;
    const ip1 = [4]u8{ 1, 2, 3, 4 };
    const ip2 = [4]u8{ 5, 6, 7, 8 };

    // 冷表必然未命中
    try std.testing.expectEqual(@as(?[4]u8, null), dnsLookup("a.example.com", now));

    // 命中 + TTL 边界（到期整点按未命中）
    dnsInsert("a.example.com", ip1, now);
    try std.testing.expectEqual(ip1, dnsLookup("a.example.com", now).?);
    try std.testing.expectEqual(ip1, dnsLookup("a.example.com", now + dns_cache_ttl_ms - 1).?);
    try std.testing.expectEqual(@as(?[4]u8, null), dnsLookup("a.example.com", now + dns_cache_ttl_ms));

    // 同域名重复插入 = 刷新（不是新增一条）
    dnsInsert("a.example.com", ip2, now);
    try std.testing.expectEqual(ip2, dnsLookup("a.example.com", now).?);
    try std.testing.expectEqual(@as(usize, 1), dns_len);

    // 不同域名互不干扰
    dnsInsert("b.example.com", ip1, now);
    try std.testing.expectEqual(ip2, dnsLookup("a.example.com", now).?);
    try std.testing.expectEqual(ip1, dnsLookup("b.example.com", now).?);

    // 主动失效（CDN 换 IP 场景的兜底）
    dnsInvalidate("a.example.com");
    try std.testing.expectEqual(@as(?[4]u8, null), dnsLookup("a.example.com", now));
    try std.testing.expectEqual(ip1, dnsLookup("b.example.com", now).?); // 只失效指定域名

    // 失效不存在的域名 = 无操作，不许 panic
    dnsInvalidate("nope.example.com");
    dnsInvalidate("");

    // 超长主机名：既不入库也不越界
    var long_buf: [dns_max_host_len + 1]u8 = undefined;
    @memset(&long_buf, 'x');
    const long: []const u8 = &long_buf;
    dnsInvalidate(long);
    try std.testing.expectEqual(@as(?[4]u8, null), dnsLookup(long, now));
    try std.testing.expectEqual(@as(usize, 2), dns_len); // 未新增条目

    // 容量上界：灌到超过容量后长度封顶，先入库的仍可命中
    reset();
    var i: usize = 0;
    while (i < dns_max_entries + 20) : (i += 1) {
        var hb: [64]u8 = undefined;
        const h = std.fmt.bufPrint(&hb, "h{d}.test", .{i}) catch break;
        dnsInsert(h, ip1, now);
    }
    try std.testing.expectEqual(dns_max_entries, dns_len);
    try std.testing.expectEqual(ip1, dnsLookup("h0.test", now).?);
    // 超出容量后被放弃的那条不可命中（未逐出语义的反向验证）
    var hb2: [64]u8 = undefined;
    const overflowed = std.fmt.bufPrint(&hb2, "h{d}.test", .{dns_max_entries}) catch unreachable;
    try std.testing.expectEqual(@as(?[4]u8, null), dnsLookup(overflowed, now));
}

test "M35: TTL<=0 时缓存整体关闭（等价于原 resolveV4 路径）" {
    const orig = dns_cache_ttl_ms;
    defer dns_cache_ttl_ms = orig;
    dns_cache_ttl_ms = 0;
    // 关闭状态下查表必须恒空 —— 保证"关掉缓存"是条可达的退路
    try std.testing.expectEqual(@as(?[4]u8, null), dnsLookup("anything.local", sys.nowMonoMs()));
    dnsInsert("anything.local", [4]u8{ 9, 9, 9, 9 }, sys.nowMonoMs());
}
