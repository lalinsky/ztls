//! Random bytes from AWS-LC's DRBG, which seeds itself from the OS.

const std = @import("std");
const c = @import("c");

pub fn bytes(buf: []u8) void {
    if (buf.len == 0) return;
    // AWS-LC aborts rather than return failure here.
    const ok = c.RAND_bytes(buf.ptr, buf.len);
    std.debug.assert(ok == 1);
}

test "two draws differ" {
    var a: [32]u8 = undefined;
    var b: [32]u8 = undefined;
    bytes(&a);
    bytes(&b);
    try std.testing.expect(!std.mem.eql(u8, &a, &b));
}
