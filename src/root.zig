//! ztls: TLS 1.3 on AWS-LC's libcrypto. See DESIGN.md.

const std = @import("std");

pub const crypto = @import("crypto.zig");

test {
    std.testing.refAllDecls(@This());
}
