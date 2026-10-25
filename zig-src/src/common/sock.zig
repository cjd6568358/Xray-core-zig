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
