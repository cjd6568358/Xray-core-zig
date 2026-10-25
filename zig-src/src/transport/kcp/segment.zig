//! mKCP segment 线格式（§5.10 表 5-5；逐行对照 transport/internet/kcp/segment.go +
//! io.go @ v26.10.21）。全大端；单个 UDP 报文可背靠背多段；切分中途遇非法段
//! 即停（已解析的合法段照常处理——listener.go:75-77 语义，调用方负责）。
//!
//! 本 fork（PR #5560）无加密/伪装层：线路上就是明文 segment。
//! 内存约定：Segment 由 allocator 创建（data 的 payload 归 segment 所有），
//! 用完必须 deinit 归还。

const std = @import("std");

pub const Command = enum(u8) {
    ack = 0,
    data = 1,
    terminate = 2,
    ping = 3,
    _,

    pub fn isKnown(self: Command) bool {
        return switch (self) {
            .ack, .data, .terminate, .ping => true,
            else => false,
        };
    }
};

/// SegmentOptionClose = 1（opt 位；其余位保留）
pub const OPTION_CLOSE: u8 = 1;

pub const data_segment_overhead: usize = 18; // conv2+cmd1+opt1+ts4+num4+snext4+len2

pub const ack_number_limit: usize = 128;

pub const DataSegment = struct {
    conv: u16 = 0,
    option: u8 = 0,
    timestamp: u32 = 0,
    number: u32 = 0,
    sending_next: u32 = 0,
    /// 归 segment 所有（dupe 或移交）
    payload: []u8 = &.{},
    /// 发送侧私有（重传计时/次数）
    timeout: u32 = 0,
    transmit: u32 = 0,

    pub fn byteSize(self: *const DataSegment) usize {
        return data_segment_overhead + self.payload.len;
    }

    pub fn serialize(self: *const DataSegment, b: []u8) void {
        std.mem.writeInt(u16, b[0..2], self.conv, .big);
        b[2] = @intFromEnum(Command.data);
        b[3] = self.option;
        std.mem.writeInt(u32, b[4..8], self.timestamp, .big);
        std.mem.writeInt(u32, b[8..12], self.number, .big);
        std.mem.writeInt(u32, b[12..16], self.sending_next, .big);
        std.mem.writeInt(u16, b[16..18], @intCast(self.payload.len), .big);
        @memcpy(b[18..][0..self.payload.len], self.payload);
    }
};

pub const AckSegment = struct {
    conv: u16 = 0,
    option: u8 = 0,
    receiving_window: u32 = 0,
    receiving_next: u32 = 0,
    timestamp: u32 = 0,
    /// 固定容量：写侧 IsFull 封顶 limit（≤128）；解析侧 count ≤ 255（字节上限）
    numbers: [255]u32 = undefined,
    count: usize = 0,

    pub fn putTimestamp(self: *AckSegment, timestamp: u32) void {
        // 无符号回绕比较（Go: timestamp-s.Timestamp < 0x7FFFFFFF）
        if (timestamp -% self.timestamp < 0x7FFFFFFF) {
            self.timestamp = timestamp;
        }
    }

    pub fn putNumber(self: *AckSegment, number: u32) void {
        if (self.count < self.numbers.len) {
            self.numbers[self.count] = number;
            self.count += 1;
        }
    }

    pub fn isFull(self: *const AckSegment, limit: usize) bool {
        return self.count >= limit;
    }

    pub fn isEmpty(self: *const AckSegment) bool {
        return self.count == 0;
    }

    pub fn byteSize(self: *const AckSegment) usize {
        return 2 + 1 + 1 + 4 + 4 + 4 + 1 + self.count * 4;
    }

    pub fn serialize(self: *const AckSegment, b: []u8) void {
        std.mem.writeInt(u16, b[0..2], self.conv, .big);
        b[2] = @intFromEnum(Command.ack);
        b[3] = self.option;
        std.mem.writeInt(u32, b[4..8], self.receiving_window, .big);
        std.mem.writeInt(u32, b[8..12], self.receiving_next, .big);
        std.mem.writeInt(u32, b[12..16], self.timestamp, .big);
        b[16] = @intCast(self.count);
        var n: usize = 17;
        for (self.numbers[0..self.count]) |number| {
            std.mem.writeInt(u32, b[n..][0..4], number, .big);
            n += 4;
        }
    }
};

pub const CmdOnlySegment = struct {
    conv: u16 = 0,
    cmd: Command = .ping,
    option: u8 = 0,
    sending_next: u32 = 0,
    receiving_next: u32 = 0,
    peer_rto: u32 = 0,

    pub fn byteSize(self: *const CmdOnlySegment) usize {
        _ = self;
        return 2 + 1 + 1 + 4 + 4 + 4;
    }

    pub fn serialize(self: *const CmdOnlySegment, b: []u8) void {
        std.mem.writeInt(u16, b[0..2], self.conv, .big);
        b[2] = @intFromEnum(self.cmd);
        b[3] = self.option;
        std.mem.writeInt(u32, b[4..8], self.sending_next, .big);
        std.mem.writeInt(u32, b[8..12], self.receiving_next, .big);
        std.mem.writeInt(u32, b[12..16], self.peer_rto, .big);
    }
};

pub const Segment = union(enum) {
    data: DataSegment,
    ack: AckSegment,
    cmd: CmdOnlySegment,

    pub fn conversation(self: Segment) u16 {
        return switch (self) {
            inline else => |*s| s.conv,
        };
    }

    pub fn command(self: Segment) Command {
        return switch (self) {
            .data => .data,
            .ack => .ack,
            .cmd => |s| s.cmd,
        };
    }

    pub fn option(self: Segment) u8 {
        return switch (self) {
            inline else => |*s| s.option,
        };
    }

    pub fn byteSize(self: Segment) usize {
        return switch (self) {
            .data => |*s| s.byteSize(),
            .ack => |*s| s.byteSize(),
            .cmd => |*s| s.byteSize(),
        };
    }

    pub fn serialize(self: Segment, b: []u8) void {
        switch (self) {
            .data => |*s| s.serialize(b),
            .ack => |*s| s.serialize(b),
            .cmd => |*s| s.serialize(b),
        }
    }

    /// 释放 data payload（ack/cmd 无堆内存）
    pub fn deinit(self: Segment, allocator: std.mem.Allocator) void {
        switch (self) {
            .data => |s| {
                if (s.payload.len > 0) allocator.free(s.payload);
            },
            else => {},
        }
    }
};

/// io.go KCPPacketReader：整包 → 段列表（堆分配；中途非法即停，返回已解析段）。
/// 调用方对每个段调用 deinit。返回空列表 = 整包无效（listener 丢弃并记日志）。
pub fn readPacket(allocator: std.mem.Allocator, buf_in: []const u8, out: *std.ArrayList(Segment)) !void {
    var rest = buf_in;
    while (rest.len > 0) {
        const seg = readSegment(allocator, rest) orelse break; // 非法段：停止本包解析
        rest = seg.consumed;
        try out.append(allocator, seg.segment);
    }
}

pub const ReadResult = struct {
    segment: Segment,
    consumed: []const u8, // 该段之后的剩余字节
};

/// segment.go ReadSegment：<4 → null；cmd 未知 → CmdOnlySegment（Go default 分支）；
/// 段内长度不符 → null（半包/错包，调用方停）。
pub fn readSegment(allocator: std.mem.Allocator, buf_in: []const u8) ?ReadResult {
    if (buf_in.len < 4) return null;
    const conv = std.mem.readInt(u16, buf_in[0..2], .big);
    const cmd: Command = @enumFromInt(buf_in[2]);
    const opt = buf_in[3];
    var rest = buf_in[4..];

    switch (cmd) {
        .data => {
            if (rest.len < 15) return null;
            const timestamp = std.mem.readInt(u32, rest[0..4], .big);
            const number = std.mem.readInt(u32, rest[4..8], .big);
            const sending_next = std.mem.readInt(u32, rest[8..12], .big);
            const data_len = std.mem.readInt(u16, rest[12..14], .big);
            rest = rest[14..];
            if (rest.len < data_len) return null;
            const payload = allocator.dupe(u8, rest[0..data_len]) catch return null;
            rest = rest[data_len..];
            return .{ .segment = .{ .data = .{
                .conv = conv,
                .option = opt,
                .timestamp = timestamp,
                .number = number,
                .sending_next = sending_next,
                .payload = payload,
            } }, .consumed = rest };
        },
        .ack => {
            if (rest.len < 13) return null;
            var seg = AckSegment{
                .conv = conv,
                .option = opt,
                .receiving_window = std.mem.readInt(u32, rest[0..4], .big),
                .receiving_next = std.mem.readInt(u32, rest[4..8], .big),
                .timestamp = std.mem.readInt(u32, rest[8..12], .big),
            };
            const count: usize = rest[12];
            rest = rest[13..];
            if (rest.len < count * 4) return null;
            var i: usize = 0;
            while (i < count) : (i += 1) {
                seg.putNumber(std.mem.readInt(u32, rest[0..4], .big));
                rest = rest[4..];
            }
            return .{ .segment = .{ .ack = seg }, .consumed = rest };
        },
        else => {
            // CmdOnly（含未知 cmd——Go default 分支原样接受）
            if (rest.len < 12) return null;
            const seg = CmdOnlySegment{
                .conv = conv,
                .cmd = cmd,
                .option = opt,
                .sending_next = std.mem.readInt(u32, rest[0..4], .big),
                .receiving_next = std.mem.readInt(u32, rest[4..8], .big),
                .peer_rto = std.mem.readInt(u32, rest[8..12], .big),
            };
            rest = rest[12..];
            return .{ .segment = .{ .cmd = seg }, .consumed = rest };
        },
    }
}

// ============================ 测试 ============================

test "segment roundtrip: data / ack / cmd（背靠背多段）" {
    const a = std.testing.allocator;

    // 构造：data("hello") + ack(2 numbers) + cmd(ping)
    var pkt: std.ArrayList(u8) = .empty;
    defer pkt.deinit(a);

    const d = DataSegment{
        .conv = 0x1234,
        .option = OPTION_CLOSE,
        .timestamp = 1000,
        .number = 7,
        .sending_next = 3,
        .payload = try a.dupe(u8, "hello"),
    };
    var dbuf: [64]u8 = undefined;
    d.serialize(dbuf[0..d.byteSize()]);
    try pkt.appendSlice(a, dbuf[0..d.byteSize()]);
    a.free(d.payload);

    var ack = AckSegment{ .conv = 0x1234, .receiving_window = 100, .receiving_next = 42, .timestamp = 2000 };
    ack.putNumber(5);
    ack.putNumber(6);
    const ack_size = ack.byteSize();
    var abuf: [256]u8 = undefined;
    ack.serialize(abuf[0..ack_size]);
    try pkt.appendSlice(a, abuf[0..ack_size]);

    const c = CmdOnlySegment{ .conv = 0x1234, .cmd = .ping, .sending_next = 9, .receiving_next = 11, .peer_rto = 300 };
    const c_size = c.byteSize();
    var cbuf: [32]u8 = undefined;
    c.serialize(cbuf[0..c_size]);
    try pkt.appendSlice(a, cbuf[0..c_size]);

    // 解析
    var segs: std.ArrayList(Segment) = .empty;
    defer {
        for (segs.items) |s| s.deinit(a);
        segs.deinit(a);
    }
    try readPacket(a, pkt.items, &segs);
    try std.testing.expectEqual(@as(usize, 3), segs.items.len);

    try std.testing.expectEqual(Command.data, segs.items[0].command());
    try std.testing.expectEqual(@as(u16, 0x1234), segs.items[0].conversation());
    try std.testing.expectEqual(@as(u8, OPTION_CLOSE), segs.items[0].option());
    try std.testing.expectEqual(@as(u32, 7), segs.items[0].data.number);
    try std.testing.expectEqualStrings("hello", segs.items[0].data.payload);

    try std.testing.expectEqual(Command.ack, segs.items[1].command());
    try std.testing.expectEqual(@as(usize, 2), segs.items[1].ack.count);
    try std.testing.expectEqual(@as(u32, 5), segs.items[1].ack.numbers[0]);
    try std.testing.expectEqual(@as(u32, 6), segs.items[1].ack.numbers[1]);

    try std.testing.expectEqual(Command.ping, segs.items[2].command());
    try std.testing.expectEqual(@as(u32, 300), segs.items[2].cmd.peer_rto);
}

test "segment: 截断/半包 → 停止且保留已解析段（listener.go 语义）" {
    const a = std.testing.allocator;
    var pkt: std.ArrayList(u8) = .empty;
    defer pkt.deinit(a);

    // 完整 data("ab")
    const d = DataSegment{ .conv = 1, .number = 0, .payload = try a.dupe(u8, "ab") };
    var dbuf: [64]u8 = undefined;
    d.serialize(dbuf[0..d.byteSize()]);
    try pkt.appendSlice(a, dbuf[0..d.byteSize()]);
    a.free(d.payload);
    // 半个 data 头（声称 payload 10 字节但只有 2）
    try pkt.appendSlice(a, &.{ 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10, 1, 2 });

    var segs: std.ArrayList(Segment) = .empty;
    defer {
        for (segs.items) |s| s.deinit(a);
        segs.deinit(a);
    }
    try readPacket(a, pkt.items, &segs);
    try std.testing.expectEqual(@as(usize, 1), segs.items.len); // 第二段被丢弃
    try std.testing.expectEqualStrings("ab", segs.items[0].data.payload);
}

test "segment: 未知 cmd 按 CmdOnly 解析（Go default 分支）" {
    const a = std.testing.allocator;
    const raw = [_]u8{ 0, 5, 0x77, 0, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3 };
    const r = readSegment(a, raw[0..]) orelse return error.TestUnexpectedResult;
    defer r.segment.deinit(a);
    try std.testing.expectEqual(@intFromEnum(Command.ping) + 116, @intFromEnum(r.segment.command()));
    try std.testing.expectEqual(@as(u32, 1), r.segment.cmd.sending_next);
}

test "ack putTimestamp 回绕语义" {
    var ack = AckSegment{ .timestamp = 0xFFFFFFFF };
    ack.putTimestamp(100); // 100 - 0xFFFFFFFF 回绕后 = 100 < 0x7FFFFFFF → 更新
    try std.testing.expectEqual(@as(u32, 100), ack.timestamp);
    ack.timestamp = 1000;
    ack.putTimestamp(1000 + 0x80000000); // 差值 ≥ 0x7FFFFFFF → 不更新
    try std.testing.expectEqual(@as(u32, 1000), ack.timestamp);
}
