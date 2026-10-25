//! VLESS / VMess 入站 settings 解析（上游 infra/conf/vless.go、vmess.go 子集）。

const std = @import("std");
const uuid = @import("../common/uuid.zig");

pub const ConfError = error{
    InvalidUser,
    UnsupportedFlow,
    EncryptionInInbound,
    DecryptionNotNone,
    InvalidUuid,
    OutOfMemory,
};

pub const VlessClient = struct {
    id: []const u8,
    email: []const u8 = "",
    flow: []const u8 = "",
    encryption: []const u8 = "",

    pub const Built = struct {
        uuid: uuid.Uuid,
        email: []const u8,
        cmd_key: [16]u8,
    };

    /// processClient 语义：UUID 严格解析；flow 仅 ""（Phase 1）；encryption 必须缺省
    pub fn build(self: *const VlessClient) ConfError!Built {
        const u = uuid.Uuid.parse(self.id) catch return ConfError.InvalidUuid;
        if (self.flow.len != 0) {
            return ConfError.UnsupportedFlow; // VLESS users: "flow" doesn't support "..." in this version
        }
        if (self.encryption.len != 0) {
            return ConfError.EncryptionInInbound; // VLESS users: "encryption" should not be in inbound settings
        }
        return .{ .uuid = u, .email = self.email, .cmd_key = uuid.cmdKeyOf(u) };
    }
};

/// 回落配置（对照 proxy/vless/inbound config.pb.go Fallback）
pub const Fallback = struct {
    name: []const u8 = "",
    alpn: []const u8 = "",
    path: []const u8 = "",
    /// dial 类型（上游 fb.Type，默认 tcp）
    type: []const u8 = "tcp",
    dest: []const u8 = "",
    /// 0 = 不发 PROXY 头；1 = PROXY protocol v1（文本）
    xver: u64 = 0,
};

/// JSON 原始形态：dest 兼容 string 与 number（上游 protojson 对 string 字段
/// 容错数字，测试数据 `"dest": 80` 即依赖此行为；std.json 严格类型需自行归一）
const FallbackRaw = struct {
    name: []const u8 = "",
    alpn: []const u8 = "",
    path: []const u8 = "",
    type: []const u8 = "tcp",
    dest: std.json.Value = .null,
    xver: u64 = 0,
};

/// dest 归一：string 原样；number 格式化为十进制字符串（protojson 容错语义）
fn normalizeDest(arena: std.mem.Allocator, v: std.json.Value) []const u8 {
    return switch (v) {
        .string => |s| s,
        .integer => |i| std.fmt.allocPrint(arena, "{d}", .{i}) catch "",
        .float => |f| std.fmt.allocPrint(arena, "{d}", .{f}) catch "",
        else => "",
    };
}

pub const VlessInboundConfig = struct {
    clients: []const VlessClient = &.{},
    decryption: []const u8 = "",
    fallbacks: []const FallbackRaw = &.{},

    pub const Built = struct {
        users: []const VlessClient.Built,
        fallbacks: []const Fallback = &.{},
    };

    pub fn build(self: *const VlessInboundConfig, arena: std.mem.Allocator) ConfError!Built {
        if (!std.mem.eql(u8, self.decryption, "none")) {
            return ConfError.DecryptionNotNone; // VLESS "decryption" only supports "none" for now.
        }
        var users: std.ArrayList(VlessClient.Built) = .empty;
        errdefer users.deinit(arena);
        for (self.clients) |*c| {
            const u = try c.build();
            users.append(arena, u) catch return error.OutOfMemory;
        }
        // fallbacks：raw → Built（dest 数字归一为字符串）
        var fbs: std.ArrayList(Fallback) = .empty;
        errdefer fbs.deinit(arena);
        for (self.fallbacks) |raw| {
            fbs.append(arena, .{
                .name = raw.name,
                .alpn = raw.alpn,
                .path = raw.path,
                .type = raw.type,
                .dest = normalizeDest(arena, raw.dest),
                .xver = raw.xver,
            }) catch return error.OutOfMemory;
        }
        return .{ .users = users.items, .fallbacks = fbs.items };
    }
};

pub const VmessClient = struct {
    id: []const u8,
    email: []const u8 = "",
    level: u8 = 0,
};

pub const VmessInboundConfig = struct {
    clients: []const VmessClient = &.{},
};

test "vless client build + cmd key" {
    const c = VlessClient{ .id = "de53e864-8530-4212-a3d7-c31e60b62e91", .email = "pb8lpgli" };
    const b = try c.build();
    var hexbuf: [32]u8 = undefined;
    _ = std.fmt.bufPrint(&hexbuf, "{s}", .{std.fmt.bytesToHex(b.cmd_key, .lower)}) catch unreachable;
    try std.testing.expectEqualStrings("d67b69fc215b108c042ab60cf5f01127", hexbuf[0..]);
}

test "vless rejects flow / encryption / bad decryption" {
    try std.testing.expectError(ConfError.UnsupportedFlow, (VlessClient{ .id = "de53e864-8530-4212-a3d7-c31e60b62e91", .flow = "xtls-rprx-vision" }).build());
    try std.testing.expectError(ConfError.EncryptionInInbound, (VlessClient{ .id = "de53e864-8530-4212-a3d7-c31e60b62e91", .encryption = "mlkem768" }).build());
    const cfg = VlessInboundConfig{ .clients = &.{.{ .id = "de53e864-8530-4212-a3d7-c31e60b62e91" }}, .decryption = "auto" };
    try std.testing.expectError(ConfError.DecryptionNotNone, cfg.build(std.testing.allocator));
}

test "vless invalid uuid rejected" {
    // 短 UUID（1-30 字符）是上游合法形态；非法 = 0/31/>36 长度或 32-36 段内非 hex
    try std.testing.expectError(ConfError.InvalidUuid, (VlessClient{ .id = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" }).build());
    try std.testing.expectError(ConfError.InvalidUuid, (VlessClient{ .id = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" }).build());
    try std.testing.expectError(ConfError.InvalidUuid, (VlessClient{ .id = "de53e864-8530-4212-a3d7-c31e60b62eXX" }).build());
    // 短串合法
    _ = try (VlessClient{ .id = "pb8lpgli" }).build();
}
