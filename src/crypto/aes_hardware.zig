//! Under `-Dimpl=openssl`, the one part of `aead` the engine uses: whether
//! the CPU has AES instructions, for choosing between AES-GCM and
//! ChaCha20-Poly1305. OpenSSL does not say, so the CPU is asked.

const std = @import("std");
const builtin = @import("builtin");

/// Whether the CPU has the AES and carry-less multiplication instructions
/// that make AES-GCM fast. Without them OpenSSL's AES-GCM is several times
/// slower than ChaCha20-Poly1305.
pub fn hasAesHardware() bool {
    const cpu = builtin.cpu;
    switch (cpu.arch) {
        .x86_64, .x86 => {
            if (std.Target.x86.featureSetHasAll(cpu.features, .{ .aes, .pclmul })) return true;
            // CPUID leaf 1: ECX bit 25 is AES-NI, bit 1 PCLMULQDQ.
            var eax: u32 = 1;
            var ebx: u32 = undefined;
            var ecx: u32 = 0;
            var edx: u32 = undefined;
            asm volatile ("cpuid"
                : [_] "={eax}" (eax),
                  [_] "={ebx}" (ebx),
                  [_] "={ecx}" (ecx),
                  [_] "={edx}" (edx),
                : [_] "{eax}" (eax),
                  [_] "{ecx}" (ecx),
            );
            return ecx & (1 << 25) != 0 and ecx & (1 << 1) != 0;
        },
        .aarch64, .aarch64_be => {
            if (std.Target.aarch64.featureSetHasAll(cpu.features, .{.aes})) return true;
            if (builtin.os.tag == .linux) {
                // AT_HWCAP's HWCAP_AES and HWCAP_PMULL, through libc,
                // which OpenSSL needs anyway.
                const at_hwcap = 16;
                const hwcap = std.c.getauxval(at_hwcap);
                return hwcap & (1 << 3) != 0 and hwcap & (1 << 4) != 0;
            }
            return false;
        },
        else => return false,
    }
}

test "the answer is stable" {
    try std.testing.expectEqual(hasAesHardware(), hasAesHardware());
}
