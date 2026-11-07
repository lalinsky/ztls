//! The cryptography ztls uses, all from AWS-LC's libcrypto.
//!
//! Every function here is one self-contained computation: it never calls
//! back into Zig and never blocks, so a fiber may call it even if the runtime
//! moves fibers between threads. AWS-LC keeps its error queue in thread-local
//! storage; `err.take` reads and clears it right after a failing call, before
//! anything that could move the fiber.
//!
//! The declarations come from AWS-LC's headers through the build's
//! translate-c step (`src/c.h`), so struct layouts are the library's own.

const std = @import("std");

pub const c = @import("c");
pub const err = @import("crypto/err.zig");
pub const hash = @import("crypto/hash.zig");
pub const hkdf = @import("crypto/hkdf.zig");
pub const aead = @import("crypto/aead.zig");
pub const rand = @import("crypto/rand.zig");
pub const kx = @import("crypto/kx.zig");

test {
    std.testing.refAllDecls(@This());
}

test "translated headers match the linked library" {
    try std.testing.expectEqual(@as(u64, c.AWSLC_API_VERSION), @as(u64, c.awslc_api_version_num()));
}
