//! VMess AEAD 分块体（对照 common/crypto/{auth,chunk}.go + encoding/client.go
//! GenerateChunkNonce @ v26.10.21）。
//!
//! 块线格式：[尺寸段 SizeBytes][密封载荷(载荷+16B tag)][明文 padding]；
//! 尺寸值 = 密文长度(载荷+16) + padding；AEAD 尺寸段（AuthenticatedLength 选项）
//! 尺寸段本身密封（18B = 2B + 16B tag），其密钥为 auth_len KDF 派生——
//! **D5：两方向（请求/响应）均用请求侧 requestBodyKey/IV 派生**。
//! nonce：GenerateChunkNonce——计数器 u16 BE 写入 IV 前 2 字节，nonce=前 12B。
//! SHAKE 状态同一实例服务「尺寸掩码」与「padding 长度」（Go: padding = sizeParser
//! 断言），每块调用序：写侧 padding→Encode，读侧 padding→Decode（顺序一致）。

const std = @import("std");
const sys = @import("../../common/sys.zig");
const stream_mod = @import("../../core/stream.zig");
const chacha_key = @import("../../crypto/chacha_key.zig");

pub const overhead = 16;
pub const max_padding_len = 64;

pub const AeadKind = enum { aes128_gcm, chacha20_poly1305 };

/// 体加密原语（AES-128-GCM / ChaCha20-Poly1305，AAD 恒空——Go GenerateEmptyBytes）
pub const BodyCipher = struct {
    kind: AeadKind,
    key16: [16]u8 = undefined,
    key32: [32]u8 = undefined,

    pub fn initAes128Gcm(key: *const [16]u8) BodyCipher {
        return .{ .kind = .aes128_gcm, .key16 = key.* };
    }

    pub fn initChacha20Poly1305(cmd_key: *const [16]u8) BodyCipher {
        var c = BodyCipher{ .kind = .chacha20_poly1305 };
        chacha_key.generateChacha20Poly1305Key(&c.key32, cmd_key);
        return c;
    }

    /// out.len == plain.len + 16
    pub fn seal(self: *const BodyCipher, out: []u8, nonce: *const [12]u8, plain: []const u8) void {
        const c = out[0..plain.len];
        const tag = out[plain.len..][0..16];
        switch (self.kind) {
            .aes128_gcm => std.crypto.aead.aes_gcm.Aes128Gcm.encrypt(c, tag, plain, &.{}, nonce.*, self.key16),
            .chacha20_poly1305 => std.crypto.aead.chacha_poly.ChaCha20Poly1305.encrypt(c, tag, plain, &.{}, nonce.*, self.key32),
        }
    }

    /// sealed.len >= 16；out.len == sealed.len - 16；失败 → error.AuthFailed
    pub fn open(self: *const BodyCipher, out: []u8, nonce: *const [12]u8, sealed: []const u8) !void {
        const c = sealed[0..sealed.len - 16];
        const tag = sealed[sealed.len - 16..][0..16].*;
        switch (self.kind) {
            .aes128_gcm => try std.crypto.aead.aes_gcm.Aes128Gcm.decrypt(out, c, tag, &.{}, nonce.*, self.key16),
            .chacha20_poly1305 => try std.crypto.aead.chacha_poly.ChaCha20Poly1305.decrypt(out, c, tag, &.{}, nonce.*, self.key32),
        }
    }
};

/// GenerateChunkNonce：计数器写 IV 前 2 字节（BE），nonce = IV 前 12 字节
pub const ChunkNonceGen = struct {
    base: [16]u8,
    count: u16 = 0,

    pub fn init(iv: *const [16]u8) ChunkNonceGen {
        return .{ .base = iv.* };
    }

    pub fn next(self: *ChunkNonceGen, out: *[12]u8) void {
        std.mem.writeInt(u16, self.base[0..2], self.count, .big);
        self.count +%= 1;
        @memcpy(out, self.base[0..12]);
    }
};

pub const SizeKind = union(enum) {
    plain,
    /// **指针**：Go 里 padding 与 size 共用同一 ShakeSizeParser 实例
    /// （client.go:105-116 `padding = sizeParser.(PaddingLengthGenerator)`），
    /// 每块顺序：padding 耗 2B → size 耗 2B。存值会分裂成两条流（M8 互通踩坑）。
    shake: *chacha_key.ShakeSizeParser,
    aead: struct { cipher: BodyCipher, nonce: ChunkNonceGen },
};

pub fn sizeBytes(kind: *const SizeKind) usize {
    return switch (kind.*) {
        .plain, .shake => 2,
        .aead => 2 + overhead,
    };
}

fn encodeSize(kind: *SizeKind, size_val: u16, wire: []u8) void {
    switch (kind.*) {
        .plain => std.mem.writeInt(u16, wire[0..2], size_val, .big),
        .shake => |p| p.encode(size_val, wire[0..2]),
        .aead => |*a| {
            var n: [12]u8 = undefined;
            a.nonce.next(&n);
            var plain2: [2]u8 = undefined;
            std.mem.writeInt(u16, &plain2, size_val - overhead, .big);
            a.cipher.seal(wire[0..18], &n, plain2[0..]);
        },
    }
}

fn decodeSize(kind: *SizeKind, wire: []const u8) !u16 {
    switch (kind.*) {
        .plain => return std.mem.readInt(u16, wire[0..2], .big),
        .shake => |p| return p.decode(wire[0..2]),
        .aead => |*a| {
            var n: [12]u8 = undefined;
            a.nonce.next(&n);
            var plain2: [2]u8 = undefined;
            try a.cipher.open(plain2[0..], &n, wire[0..18]);
            return std.mem.readInt(u16, &plain2, .big) + overhead;
        },
    }
}

fn readFull(inner: stream_mod.Stream, out: []u8) !void {
    var off: usize = 0;
    while (off < out.len) {
        const n = try inner.read(out[off..]);
        if (n == 0) return error.EndOfStream;
        off += n;
    }
}

// ============================ 读侧 ============================

/// AuthenticationReader：从 Stream 读分块密文 → 明文载荷（Stream vtable 形态）
pub const AuthReader = struct {
    inner: stream_mod.Stream,
    alloc: std.mem.Allocator,
    cipher: BodyCipher,
    nonce: ChunkNonceGen,
    size: SizeKind,
    /// GlobalPadding：与 size.shake 同实例（Go: padding = sizeParser 断言）
    shake: ?*chacha_key.ShakeSizeParser = null,

    done: bool = false,
    /// hasSize 缓存（上游 common/crypto/auth.go:172-177 语义）：载荷段读到一半
    /// 超时向上抛之前，把已解析的 size/padding 存下来；重入时直接复用——
    /// 不得重读尺寸段（载荷字节会被当尺寸段消费 → GCM 失败 BadChunk 断连），
    /// 也不得重耗 SHAKE（padding/size 共流，M8 红线）。
    has_size: bool = false,
    p_size: u16 = 0,
    p_padding: u16 = 0,
    pending: std.ArrayList(u8) = .empty, // 已解密未消费载荷
    pending_pos: usize = 0,
    work: std.ArrayList(u8) = .empty, // 块读缓冲（可增长）
    /// 尺寸段续读进度（读超时是拷贝循环的 1s 轮询节拍，状态必须跨超时保留）
    hdr: [18]u8 = undefined,
    hdr_have: usize = 0,
    /// 载荷段续读进度
    in_chunk: bool = false,
    work_have: usize = 0,

    pub fn deinit(self: *AuthReader) void {
        self.pending.deinit(self.alloc);
        self.work.deinit(self.alloc);
    }

    fn shakePad(self: *AuthReader) u16 {
        if (self.shake) |p| return p.nextPaddingLen();
        return 0;
    }

    pub fn read(self: *AuthReader, out: []u8) anyerror!usize {
        while (true) {
            if (self.pending_pos < self.pending.items.len) {
                const n = @min(out.len, self.pending.items.len - self.pending_pos);
                @memcpy(out[0..n], self.pending.items[self.pending_pos..][0..n]);
                self.pending_pos += n;
                if (self.pending_pos == self.pending.items.len) {
                    self.pending.clearRetainingCapacity();
                    self.pending_pos = 0;
                }
                return n;
            }
            if (self.done) return 0;

            var size: u16 = undefined;
            var padding: u16 = 0;
            if (self.has_size) {
                self.has_size = false;
                size = self.p_size;
                padding = self.p_padding;
            } else {
                const sb = sizeBytes(&self.size);
                // 尺寸段可续读：超时向上抛（拷贝循环按 1s 轮询节拍重入），
                // 已读字节留在 self.hdr，状态机不丢位。
                while (self.hdr_have < sb) {
                    const n = self.inner.read(self.hdr[self.hdr_have..sb]) catch |e| {
                        if (e == error.Timeout) return e;
                        return 0; // 真错误/对端关 → EOF
                    };
                    if (n == 0) return 0; // 干净 EOF
                    self.hdr_have += n;
                }
                self.hdr_have = 0;
                padding = self.shakePad();
                size = decodeSize(&self.size, self.hdr[0..sb]) catch return error.BadChunk;
            }

            if (size == overhead + padding) {
                self.done = true; // 空终止块
                return 0;
            }
            if (size < overhead + padding) return error.BadChunk;

            // 读 size 字节（密封载荷 + 明文 padding）：同样可续读
            if (!self.in_chunk) {
                self.work.clearRetainingCapacity();
                self.work.resize(self.alloc, size) catch return error.OutOfMemory;
                self.work_have = 0;
                self.in_chunk = true;
            }
            while (self.work_have < size) {
                const n = self.inner.read(self.work.items[self.work_have..size]) catch |e| {
                    if (e == error.Timeout) {
                        // 载荷段超时：缓存已解析的 size/padding 后再向上抛（1s 拷贝节拍
                        // 会重入本函数）。缺少缓存时重入将重读尺寸段——载荷字节被当尺寸段
                        // 消费，AEAD 尺寸段认证失败 → BadChunk 断连（慢上行块中停顿即触发）。
                        self.has_size = true;
                        self.p_size = size;
                        self.p_padding = padding;
                        return e;
                    }
                    return error.BadChunk; // 真错误
                };
                if (n == 0) return error.BadChunk; // 块中途 EOF
                self.work_have += n;
            }
            self.in_chunk = false;
            self.work_have = 0;

            const sealed_len = size - padding;
            const plain_len = sealed_len - overhead;
            const start = self.pending.items.len;
            self.pending.resize(self.alloc, start + plain_len) catch return error.OutOfMemory;

            var nonce: [12]u8 = undefined;
            self.nonce.next(&nonce);
            self.cipher.open(self.pending.items[start..][0..plain_len], &nonce, self.work.items[0..sealed_len]) catch {
                return error.BadChunk;
            };
        }
    }

    pub fn stream(self: *AuthReader) stream_mod.Stream {
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
        const self: *AuthReader = @ptrCast(@alignCast(ctx));
        return self.read(out);
    }

    fn writeAllImpl(_: *anyopaque, _: []const u8) anyerror!void {
        return error.NotSupported;
    }

    fn closeImpl(_: *anyopaque) void {}

    fn setTimeoutImpl(ctx: *anyopaque, ms: i64) void {
        const self: *AuthReader = @ptrCast(@alignCast(ctx));
        self.inner.setTimeout(ms);
    }

    fn shutdownWriteImpl(ctx: *anyopaque) void {
        const self: *AuthReader = @ptrCast(@alignCast(ctx));
        self.inner.shutdownWrite();
    }
};

// ============================ 写侧 ============================

/// AuthenticationWriter：载荷分块密封 → Stream；空载荷 = 空终止块
pub const AuthWriter = struct {
    inner: stream_mod.Stream,
    cipher: BodyCipher,
    nonce: ChunkNonceGen,
    size: SizeKind,
    shake: ?*chacha_key.ShakeSizeParser = null,
    alloc: std.mem.Allocator,

    pub fn deinit(self: *AuthWriter) void {
        _ = self;
    }

    fn shakePad(self: *AuthWriter) u16 {
        if (self.shake) |p| return p.nextPaddingLen();
        return 0;
    }

    fn chunkPayloadMax(self: *AuthWriter) usize {
        const max_pad: usize = if (self.shake != null) max_padding_len else 0;
        return 8192 - overhead - sizeBytes(&self.size) - max_pad;
    }

    /// emit：单块（含空载荷终止块）
    fn emit(self: *AuthWriter, payload: []const u8) anyerror!void {
        var padding: u16 = 0;
        padding = self.shakePad();
        const enc_len = payload.len + overhead;
        const size_val: u16 = @intCast(enc_len + padding);

        const sb = sizeBytes(&self.size);
        var wire: [18]u8 = undefined;
        encodeSize(&self.size, size_val, wire[0..sb]);

        var nonce: [12]u8 = undefined;
        self.nonce.next(&nonce);
        const sealed_len = payload.len + overhead;
        var sealed: [8192]u8 = undefined;
        self.cipher.seal(sealed[0..sealed_len], &nonce, payload);
        const pad_bytes: ?[max_padding_len]u8 = if (padding > 0) blk: {
            var p: [max_padding_len]u8 = undefined;
            sys.randomBytes(p[0..padding]);
            break :blk p;
        } else null;

        try self.inner.writeAll(wire[0..sb]);
        try self.inner.writeAll(sealed[0..sealed_len]);
        if (pad_bytes) |p| {
            try self.inner.writeAll(p[0..padding]);
        }
    }

    /// Go WriteMultiBuffer：空输入 → 空终止块；Stream 模式按 chunkPayloadMax 切分
    pub fn writeAll(self: *AuthWriter, data: []const u8) anyerror!void {
        if (data.len == 0) {
            try self.emit(&.{});
            return;
        }
        const cap = self.chunkPayloadMax();
        var off: usize = 0;
        while (off < data.len) {
            const n = @min(cap, data.len - off);
            try self.emit(data[off..][0..n]);
            off += n;
        }
    }

    pub fn stream(self: *AuthWriter) stream_mod.Stream {
        return .{
            .ctx = self,
            .readFn = readImpl,
            .writeAllFn = writeAllImpl,
            .closeFn = closeImpl,
            .setTimeoutFn = setTimeoutImpl,
            .shutdownWriteFn = shutdownWriteImpl,
        };
    }

    fn readImpl(_: *anyopaque, _: []u8) anyerror!usize {
        return error.NotSupported;
    }

    fn writeAllImpl(ctx: *anyopaque, data: []const u8) anyerror!void {
        const self: *AuthWriter = @ptrCast(@alignCast(ctx));
        return self.writeAll(data);
    }

    fn closeImpl(_: *anyopaque) void {}

    fn setTimeoutImpl(ctx: *anyopaque, ms: i64) void {
        const self: *AuthWriter = @ptrCast(@alignCast(ctx));
        self.inner.setTimeout(ms);
    }

    fn shutdownWriteImpl(ctx: *anyopaque) void {
        const self: *AuthWriter = @ptrCast(@alignCast(ctx));
        self.inner.shutdownWrite();
    }
};

// ============================ 测试 ============================

test "chunk：AES-GCM 圆环（掩码+padding+AEAD 尺寸全开）" {
    const a = std.testing.allocator;
    var pair = try @import("../../testing/echo.zig").socketpairClient(a);
    defer {
        pair.test_side.close();
        pair.deinit();
    }

    var iv: [16]u8 = undefined;
    for (&iv, 0..) |*c, i| c.* = @intCast(i);
    var key: [16]u8 = undefined;
    for (&key, 0..) |*c, i| c.* = @intCast(200 - i);

    var shake = chacha_key.ShakeSizeParser.init(iv[0..]);
    var shake_r = chacha_key.ShakeSizeParser.init(iv[0..]); // 读侧独立实例（Go：client/server 各自持有）

    const cipher = BodyCipher.initAes128Gcm(&key);
    const aead_size = SizeKind{ .aead = .{ .cipher = BodyCipher.initAes128Gcm(&key), .nonce = ChunkNonceGen.init(&iv) } };

    var w = AuthWriter{ .inner = pair.testLink().writer, .cipher = cipher, .nonce = ChunkNonceGen.init(&iv), .size = aead_size, .shake = &shake, .alloc = a };
    var r = AuthReader{ .inner = pair.link().reader, .alloc = a, .cipher = cipher, .nonce = ChunkNonceGen.init(&iv), .size = aead_size, .shake = &shake_r };
    defer r.deinit();
    defer w.deinit();

    const unit = "vmess chunked body payload - 0123456789";
    const payload = blk: {
        var buf: [unit.len * 20]u8 = undefined;
        var i: usize = 0;
        while (i < 20) : (i += 1) {
            @memcpy(buf[i * unit.len ..][0..unit.len], unit);
        }
        break :blk buf[0..];
    }; // 760B → 多块（0.17 无字符串 ** 重复运算符，comptime 拼装为切片）
    const wt = try std.Thread.spawn(.{ .stack_size = sys.crypto_thread_stack }, writerMain, .{ &w, payload });
    var got: std.ArrayList(u8) = .empty;
    defer got.deinit(a);
    var rb: [4096]u8 = undefined;
    var buf_read = r.stream();
    while (got.items.len < payload.len) {
        const n = try buf_read.read(&rb);
        if (n == 0) break;
        try got.appendSlice(a, rb[0..n]);
    }
    wt.join();
    try std.testing.expectEqualStrings(payload, got.items);
}

test "chunk：掩码+padding 共享 SHAKE 实例（Go 语义；M8 互通回归）" {
    // Go client.go:105-116：padding 即 sizeParser 本身——每块先 padding 耗 2B、
    // 再 size 耗 2B，同一条 SHAKE 流。此前存值拷贝会分裂两流 → 对端 size 解出垃圾。
    const a = std.testing.allocator;
    var pair = try @import("../../testing/echo.zig").socketpairClient(a);
    defer {
        pair.test_side.close();
        pair.deinit();
    }
    var iv: [16]u8 = undefined;
    for (&iv, 0..) |*c, i| c.* = @intCast(i);
    var key: [16]u8 = undefined;
    for (&key, 0..) |*c, i| c.* = @intCast(200 - i);

    var shake_w = chacha_key.ShakeSizeParser.init(iv[0..]);
    var shake_r = chacha_key.ShakeSizeParser.init(iv[0..]);
    const cipher = BodyCipher.initAes128Gcm(&key);
    var w = AuthWriter{ .inner = pair.testLink().writer, .cipher = cipher, .nonce = ChunkNonceGen.init(&iv), .size = .{ .shake = &shake_w }, .shake = &shake_w, .alloc = a };
    var r = AuthReader{ .inner = pair.link().reader, .alloc = a, .cipher = cipher, .nonce = ChunkNonceGen.init(&iv), .size = .{ .shake = &shake_r }, .shake = &shake_r };
    defer r.deinit();
    defer w.deinit();

    const payload = "shared shake stream: padding then size, per chunk";
    const wt = try std.Thread.spawn(.{ .stack_size = sys.crypto_thread_stack }, writerMain, .{ &w, payload });
    var got: std.ArrayList(u8) = .empty;
    defer got.deinit(a);
    var rb: [256]u8 = undefined;
    var buf_read = r.stream();
    while (got.items.len < payload.len) {
        const n = try buf_read.read(&rb);
        if (n == 0) break;
        try got.appendSlice(a, rb[0..n]);
    }
    wt.join();
    try std.testing.expectEqualStrings(payload, got.items);
}

fn writerMain(w: *AuthWriter, payload: []const u8) void {
    w.writeAll(payload) catch return;
    w.writeAll(&.{}) catch return; // 空终止块
}

test "chunk：ChaCha20-Poly1305 小载荷 + 空终止块" {
    const a = std.testing.allocator;
    var pair = try @import("../../testing/echo.zig").socketpairClient(a);
    defer {
        pair.test_side.close();
        pair.deinit();
    }

    var iv: [16]u8 = undefined;
    for (&iv, 0..) |*c, i| c.* = @intCast(16 - i);
    var cmd_key: [16]u8 = undefined;
    for (&cmd_key, 0..) |*c, i| c.* = @intCast(i * 3);

    const cipher = BodyCipher.initChacha20Poly1305(&cmd_key);
    var w = AuthWriter{ .inner = pair.testLink().writer, .cipher = cipher, .nonce = ChunkNonceGen.init(&iv), .size = .plain, .alloc = a };
    var r = AuthReader{ .inner = pair.link().reader, .alloc = a, .cipher = cipher, .nonce = ChunkNonceGen.init(&iv), .size = .plain };
    defer r.deinit();
    defer w.deinit();

    const wt = try std.Thread.spawn(.{ .stack_size = sys.crypto_thread_stack }, writerMain, .{ &w, "tiny" });
    var rb: [64]u8 = undefined;
    var buf_read = r.stream();
    var got: std.ArrayList(u8) = .empty;
    defer got.deinit(a);
    while (true) {
        const n = try buf_read.read(&rb);
        if (n == 0) break; // 空终止块 → EOF
        try got.appendSlice(a, rb[0..n]);
    }
    wt.join();
    try std.testing.expectEqualStrings("tiny", got.items);
}
