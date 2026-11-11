//! Builds AWS-LC's libcrypto with the Zig build system, no CMake, Perl or Go.
//!
//! The file lists come from upstream's CMake build through gen_sources.py;
//! see that script for how to regenerate them after an upgrade. Targets
//! without a list build the portable C code with OPENSSL_NO_ASM.

const std = @import("std");
const sources = @import("sources.zig");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const upstream = b.dependency("upstream", .{});

    const mod = b.createModule(.{
        .target = target,
        .optimize = optimize,
        .link_libc = true,
        // Constant-time code does things UBSan traps on (shifts of signed
        // values, unaligned loads behind memcpy-free casts); upstream does not
        // build with it either.
        .sanitize_c = .off,
    });

    const t = target.result;
    const platform: ?sources.Target = switch (t.os.tag) {
        .linux => switch (t.cpu.arch) {
            .x86_64 => sources.x86_64_linux,
            .aarch64 => sources.aarch64_linux,
            else => null,
        },
        .macos => switch (t.cpu.arch) {
            .aarch64 => sources.aarch64_macos,
            else => null,
        },
        else => null,
    };

    const defines: []const []const u8 = if (platform) |p| p.defines else &.{
        "BORINGSSL_IMPLEMENTATION",
        "BORINGSSL_RELEASE_BUILD",
        "AWS_LC_STDALIGN_AVAILABLE",
        "AWS_LC_BUILTIN_SWAP_SUPPORTED",
        "OPENSSL_NO_ASM",
        "DISABLE_CPU_JITTER_ENTROPY",
    };
    for (defines) |d| {
        if (std.mem.indexOfScalar(u8, d, '=')) |eq| {
            mod.addCMacro(d[0..eq], d[eq + 1 ..]);
        } else {
            mod.addCMacro(d, "1");
        }
    }
    if (t.os.tag == .windows) {
        // As upstream's CMakeLists.txt; WIN32_LEAN_AND_MEAN also keeps
        // wincrypt.h's X509_NAME macro out of the X.509 code. Windows has
        // no assembly here: upstream's is NASM, which Zig cannot assemble.
        mod.addCMacro("WIN32_LEAN_AND_MEAN", "1");
        mod.addCMacro("NOMINMAX", "1");
        mod.addCMacro("_CRT_SECURE_NO_WARNINGS", "1");
        mod.linkSystemLibrary("ws2_32", .{});
    }
    // Upstream sets this on the FIPS module and the assembly only; it just
    // keeps s2n-bignum's symbols hidden, which is right for everything.
    mod.addCMacro("S2N_BN_HIDE_SYMBOLS", "1");

    mod.addIncludePath(upstream.path("include"));
    mod.addIncludePath(upstream.path("third_party/s2n-bignum/s2n-bignum-imported/include"));

    const c_flags: []const []const u8 = &.{
        "-std=gnu11",
        "-fno-common",
        "-fvisibility=hidden",
        "-Wno-unused-parameter",
    };
    mod.addCSourceFiles(.{
        .root = upstream.path(""),
        .files = sources.c,
        .flags = c_flags,
    });
    if (platform) |p| {
        mod.addCSourceFiles(.{
            .root = upstream.path(""),
            .files = p.@"asm",
            .flags = &.{"-Wa,--noexecstack"},
        });
    }

    const lib = b.addLibrary(.{
        .name = "crypto",
        .linkage = .static,
        .root_module = mod,
    });
    lib.installHeadersDirectory(upstream.path("include"), "", .{});
    b.installArtifact(lib);
}
