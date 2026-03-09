const std = @import("std");
const builtin = @import("builtin");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const native_target = target.result;

    // Create shared module
    const shared_mod = b.createModule(.{
        .root_source_file = b.path("src/shared/root.zig"),
        .target = target,
        .optimize = optimize,
    });

    // Server target (Linux only) - only build if targeting Linux
    const is_linux_target = native_target.os.tag == .linux;
    if (is_linux_target) {
        const server_mod = b.createModule(.{
            .root_source_file = b.path("src/server/main.zig"),
            .target = target,
            .optimize = optimize,
        });
        server_mod.addImport("shared", shared_mod);
        server_mod.linkSystemLibrary("c", .{});
        server_mod.link_libc = true;

        const server_exe = b.addExecutable(.{
            .name = "f9gfw",
            .root_module = server_mod,
        });

        b.installArtifact(server_exe);

        const server_cmd = b.addRunArtifact(server_exe);
        server_cmd.step.dependOn(b.getInstallStep());
        if (b.args) |args| {
            server_cmd.addArgs(args);
        }
        const server_step = b.step("server", "Run the server");
        server_step.dependOn(&server_cmd.step);
    }

    // Client target (Windows only) - only build if targeting Windows
    const is_windows_target = native_target.os.tag == .windows;
    if (is_windows_target) {
        const client_mod = b.createModule(.{
            .root_source_file = b.path("src/client/main.zig"),
            .target = target,
            .optimize = optimize,
        });
        client_mod.addImport("shared", shared_mod);
        client_mod.linkSystemLibrary("ws2_32", .{});
        client_mod.linkSystemLibrary("fwpuclnt", .{});
        client_mod.linkSystemLibrary("iphlpapi", .{});
        client_mod.link_libc = true;

        const client_exe = b.addExecutable(.{
            .name = "f9gfwc",
            .root_module = client_mod,
        });

        b.installArtifact(client_exe);

        const client_cmd = b.addRunArtifact(client_exe);
        client_cmd.step.dependOn(b.getInstallStep());
        if (b.args) |args| {
            client_cmd.addArgs(args);
        }
        const client_step = b.step("client", "Run the client");
        client_step.dependOn(&client_cmd.step);
    }

    // Unit tests - only test shared modules
    const test_mod = b.createModule(.{
        .root_source_file = b.path("src/test_main.zig"),
        .target = target,
        .optimize = optimize,
    });
    test_mod.addImport("shared", shared_mod);

    const unit_tests = b.addTest(.{
        .root_module = test_mod,
    });

    const run_unit_tests = b.addRunArtifact(unit_tests);
    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_unit_tests.step);
}
