const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // libcrypto is built optimized even in Debug builds: a debug AWS-LC makes
    // handshakes and tests needlessly slow and adds nothing to debugging ztls.
    const aws_lc = b.dependency("aws_lc", .{
        .target = target,
        .optimize = if (optimize == std.builtin.OptimizeMode.Debug) std.builtin.OptimizeMode.ReleaseSafe else optimize,
    });
    const libcrypto = aws_lc.artifact("crypto");

    // AWS-LC's API as a Zig module, so struct layouts come from the headers.
    const translate_c = b.addTranslateC(.{
        .root_source_file = b.path("src/c.h"),
        .target = target,
        .optimize = optimize,
    });
    translate_c.addIncludePath(libcrypto.getEmittedIncludeTree());

    const mod = b.addModule("ztls", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
        .imports = &.{.{ .name = "c", .module = translate_c.createModule() }},
    });
    mod.linkLibrary(libcrypto);

    const tests = b.addTest(.{ .root_module = mod });
    const run_tests = b.addRunArtifact(tests);
    b.step("test", "Run unit tests").dependOn(&run_tests.step);
}
