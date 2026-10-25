const std = @import("std");

pub fn build(b: *std.Build) void {
    // 默认 x86_64-linux-musl 静态（开发/测试在编译机直接跑）；
    // 设备产物：-Dtarget=aarch64-linux-musl -Drelease
    // 硬规则：静态二进制一律 musl，禁 glibc 静态。
    const target = b.standardTargetOptions(.{
        .default_target = .{ .cpu_arch = .x86_64, .os_tag = .linux, .abi = .musl },
    });
    const optimize = b.standardOptimizeOption(.{ .preferred_optimize_mode = .ReleaseSafe });
    const strip = b.option(bool, "strip", "Strip debug symbols") orelse (optimize != .debug);

    // 主二进制：xrayz（aarch64-linux-musl 静态 / native 开发）
    const mod = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
        .strip = strip,
    });

    const exe = b.addExecutable(.{ .name = "xrayz", .root_module = mod });
    b.installArtifact(exe);

    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    const run_step = b.step("run", "Run xrayz");
    run_step.dependOn(&run_cmd.step);

    // 单测：默认 native 跑（不要带 -Dtarget）；单模块（zig-src 根），src 源内测试全部收集
    const test_mod = b.createModule(.{
        .root_source_file = b.path("test_all.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });

    const unit_tests = b.addTest(.{ .root_module = test_mod });
    const run_tests = b.addRunArtifact(unit_tests);
    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_tests.step);
}
