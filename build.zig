const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const tls12 = b.option(bool, "tls12", "Build the TLS 1.2 client in (default: true)") orelse true;
    const options = b.addOptions();
    options.addOption(bool, "tls12", tls12);

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
    mod.addOptions("build_options", options);

    const tests = b.addTest(.{ .root_module = mod });
    const run_tests = b.addRunArtifact(tests);
    b.step("test", "Run unit tests").dependOn(&run_tests.step);

    // The shim BoringSSL's test runner drives; see tests/bogo/run.sh.
    const shim = b.addExecutable(.{
        .name = "bogo-shim",
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/bogo/shim.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "ztls", .module = mod }},
        }),
    });
    b.step("bogo-shim", "Build the BoGo shim").dependOn(&b.addInstallArtifact(shim, .{}).step);

    // One ztls connection to a public server; see tools/survey/run.sh.
    const probe = b.addExecutable(.{
        .name = "survey-probe",
        .root_module = b.createModule(.{
            .root_source_file = b.path("tools/survey/probe.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "ztls", .module = mod }},
        }),
    });
    b.step("survey-probe", "Build the survey probe").dependOn(&b.addInstallArtifact(probe, .{}).step);
}
