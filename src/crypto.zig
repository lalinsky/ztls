//! The cryptography ztls uses, all from AWS-LC's libcrypto, or under
//! `-Dimpl=openssl` the part of it that engine needs from OpenSSL's.
//!
//! Every function here is one self-contained computation: it never calls
//! back into Zig and never blocks, so a fiber may call it even if the runtime
//! moves fibers between threads. The library keeps its error queue in
//! thread-local storage; `err.take` reads and clears it right after a
//! failing call, before anything that could move the fiber.
//!
//! The declarations come from the library's headers through the build's
//! translate-c step (`src/c_libcrypto.h`, or `src/c_openssl.h`), so struct
//! layouts are the library's own.

const std = @import("std");

/// The system's OpenSSL rather than AWS-LC: only what the openssl engine
/// uses is here, the certificates, keys and signatures.
pub const openssl = @import("build_options").openssl;

pub const c = @import("c");
pub const err = @import("crypto/err.zig");
pub const rand = @import("crypto/rand.zig");
pub const pem = @import("crypto/pem.zig");
pub const sig = @import("crypto/sig.zig");
pub const x509 = @import("crypto/x509.zig");
// The native engine's, which OpenSSL lacks the interfaces for.
pub const hash = if (openssl) struct {} else @import("crypto/hash.zig");
pub const hkdf = if (openssl) struct {} else @import("crypto/hkdf.zig");
pub const prf = if (openssl) struct {} else @import("crypto/prf.zig");
pub const kx = if (openssl) struct {} else @import("crypto/kx.zig");
pub const aead = if (openssl) @import("crypto/aes_hardware.zig") else @import("crypto/aead.zig");

test {
    std.testing.refAllDecls(@This());
}

test "translated headers match the linked library" {
    if (openssl) {
        // The major version is the ABI; a newer minor one is compatible.
        const linked = c.OpenSSL_version_num();
        try std.testing.expectEqual(@as(u64, c.OPENSSL_VERSION_NUMBER >> 28), @as(u64, linked >> 28));
        try std.testing.expect(linked >= c.OPENSSL_VERSION_NUMBER & 0xfff00000);
    } else {
        try std.testing.expectEqual(@as(u64, c.AWSLC_API_VERSION), @as(u64, c.awslc_api_version_num()));
    }
}
