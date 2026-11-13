const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const use_asm = b.option(bool, "asm", "Build AWS-LC's assembly; false builds its portable C code, without NASM on x86_64 Windows (default: true)") orelse true;
    const impl = b.option(Impl, "impl", "native: the protocol in Zig on AWS-LC's libcrypto; libssl: AWS-LC's libssl, which is C++ (default: native)") orelse .native;
    const options = b.addOptions();
    options.addOption(bool, "libssl", impl == .libssl);

    // libcrypto is built optimized even in Debug builds: a debug AWS-LC makes
    // handshakes and tests needlessly slow and adds nothing to debugging ztls.
    const aws_lc = b.dependency("aws_lc", .{
        .target = target,
        .optimize = if (optimize == std.builtin.OptimizeMode.Debug) std.builtin.OptimizeMode.ReleaseSafe else optimize,
        .@"asm" = use_asm,
    });
    const libcrypto = aws_lc.artifact("crypto");

    // AWS-LC's API as a Zig module, so struct layouts come from the headers.
    const translate_c = b.addTranslateC(.{
        .root_source_file = switch (impl) {
            .native => b.path("src/c_libcrypto.h"),
            .libssl => b.path("src/c_libssl.h"),
        },
        .target = target,
        .optimize = optimize,
    });
    translate_c.addIncludePath(libcrypto.getEmittedIncludeTree());

    const mod = b.addModule("ztls", .{
        .root_source_file = switch (impl) {
            .native => b.path("src/root_native.zig"),
            .libssl => b.path("src/root_libssl.zig"),
        },
        .target = target,
        .optimize = optimize,
        .link_libc = true,
        .imports = &.{.{ .name = "c", .module = translate_c.createModule() }},
    });
    if (impl == .libssl) mod.linkLibrary(aws_lc.artifact("ssl"));
    mod.linkLibrary(libcrypto);
    mod.addOptions("build_options", options);

    const tests = b.addTest(.{ .root_module = mod });
    const run_tests = b.addRunArtifact(tests);
    b.step("test", "Run unit tests").dependOn(&run_tests.step);

    // The test tools below drive the native implementation only, for now.
    if (impl == .libssl) return;

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

    // The server tlsfuzzer's scripts run against; see tests/tlsfuzzer/run.sh.
    const fuzz_server = b.addExecutable(.{
        .name = "tlsfuzzer-server",
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/tlsfuzzer/server.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "ztls", .module = mod }},
        }),
    });
    b.step("tlsfuzzer-server", "Build the tlsfuzzer server").dependOn(&b.addInstallArtifact(fuzz_server, .{}).step);

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

const Impl = enum { native, libssl };
