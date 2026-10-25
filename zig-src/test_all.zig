//! 测试编译根（与 src/ 同模块树，确保 src 内文件的单测全部被收集）。
//! 运行：zig build test（x86_64-linux-musl 静态）

test {
    _ = @import("src/main.zig");
    _ = @import("src/common/mux.zig");
    _ = @import("src/app/stats.zig");
    _ = @import("src/proxy/vless/fallback.zig");
    _ = @import("src/proxy/udp_packet.zig");
    _ = @import("tests/probe_test.zig");
    _ = @import("tests/golden_test.zig");
    // M8：上游测试移植（§7.1）
    _ = @import("tests/conf_test.zig");
    _ = @import("tests/vless_test.zig");
    _ = @import("tests/vmess_test.zig");
    _ = @import("tests/ws_test.zig");
    _ = @import("tests/kcp_test.zig");
}
