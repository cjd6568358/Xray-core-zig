//! VMess 入站 settings 解析（上游 infra/conf/vmess.go 子集）。
//! alterId：上游已删除该字段，json 层静默忽略（§4.3 遗留字段容忍）。
//! security：per-client 字段照收并校验枚举（上游 inbound.Account.SecuritySettings）；
//! 服务端 AEAD 路径实际取请求头里的 security 字节，此处仅解析层保真。

const std = @import("std");
const uuid = @import("../common/uuid.zig");

pub const ConfError = error{
    InvalidUuid,
    OutOfMemory,
};

/// 上游 VMessAccount.Build 的 security 开关（infra/conf/vmess.go:26-36）：
/// aes-128-gcm=3 / chacha20-poly1305=4 / auto=2，**default → AUTO**（不报错，
/// "none"/"zero"/空串都落 AUTO——上游已删 LEGACY/NONE 路径）。
pub fn parseSecurityName(name: []const u8) u8 {
    if (std.ascii.eqlIgnoreCase(name, "aes-128-gcm")) return 0x03;
    if (std.ascii.eqlIgnoreCase(name, "chacha20-poly1305")) return 0x04;
    return 0x02; // auto / 其余
}

pub const VmessClient = struct {
    id: []const u8,
    email: []const u8 = "",
    level: u8 = 0,
    security: []const u8 = "auto",
    // alterId 不声明 —— ignore_unknown_fields 静默吞掉

    pub const Built = struct {
        uuid: uuid.Uuid,
        email: []const u8,
        cmd_key: [16]u8,
        /// 请求头 security 字节的配置侧默认（服务端实际以请求头为准；仅解析保真）
        security: u8 = 0x02,
    };

    pub fn build(self: *const VmessClient) ConfError!Built {
        const u = uuid.Uuid.parse(self.id) catch return ConfError.InvalidUuid;
        return .{ .uuid = u, .email = self.email, .cmd_key = uuid.cmdKeyOf(u), .security = parseSecurityName(self.security) };
    }
};

pub const VmessInboundConfig = struct {
    clients: []const VmessClient = &.{},

    pub const Built = struct {
        users: []const VmessClient.Built,
    };

    pub fn build(self: *const VmessInboundConfig, arena: std.mem.Allocator) ConfError!Built {
        var users: std.ArrayList(VmessClient.Built) = .empty;
        errdefer users.deinit(arena);
        for (self.clients) |*c| {
            const u = try c.build();
            users.append(arena, u) catch return error.OutOfMemory;
        }
        return .{ .users = users.items };
    }
};

test "vmess alterId silently ignored at json layer" {
    const text =
        \\{"clients":[{"id":"de53e864-8530-4212-a3d7-c31e60b62e91","alterId":0,"email":"pb8lpgli"}]}
    ;
    var parsed = try std.json.parseFromSlice(VmessInboundConfig, std.testing.allocator, text, .{ .ignore_unknown_fields = true });
    defer parsed.deinit();
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const built = try parsed.value.build(arena_state.allocator());
    try std.testing.expectEqual(@as(usize, 1), built.users.len);
    try std.testing.expectEqualStrings("pb8lpgli", built.users[0].email);
    var hexbuf: [32]u8 = undefined;
    _ = std.fmt.bufPrint(&hexbuf, "{s}", .{std.fmt.bytesToHex(built.users[0].cmd_key, .lower)}) catch unreachable;
    try std.testing.expectEqualStrings("d67b69fc215b108c042ab60cf5f01127", hexbuf[0..]);
}

test "vmess invalid uuid rejected" {
    try std.testing.expectError(ConfError.InvalidUuid, (VmessClient{ .id = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" }).build());
    try std.testing.expectError(ConfError.InvalidUuid, (VmessClient{ .id = "de53e864-8530-4212-a3d7-c31e60b62eXX" }).build());
    _ = try (VmessClient{ .id = "pb8lpgli" }).build(); // 短串合法
}
