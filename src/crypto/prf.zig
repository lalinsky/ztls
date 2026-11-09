//! The TLS 1.2 pseudorandom function (RFC 5246 §5): P_hash over HMAC with
//! the suite's hash, from AWS-LC. It derives the master secret, the key
//! block and the Finished messages.

const std = @import("std");
const assert = std.debug.assert;
const c = @import("c");
const hash = @import("hash.zig");

/// PRF(secret, label, seed1 ‖ seed2), filling all of `out`. The seed comes
/// in two parts because every use in TLS 1.2 joins two values (the two
/// randoms, or a session hash and nothing).
pub fn tls12(algorithm: hash.Algorithm, secret: []const u8, label: []const u8, seed1: []const u8, seed2: []const u8, out: []u8) void {
    assert(out.len > 0);
    const ok = c.CRYPTO_tls1_prf(algorithm.md(), out.ptr, out.len, secret.ptr, secret.len, label.ptr, label.len, seed1.ptr, seed1.len, seed2.ptr, seed2.len);
    // Fails only on misuse, such as a hash it does not take.
    assert(ok == 1);
}

const testing = std.testing;

/// P_hash written out from RFC 5246 §5 over std.crypto's HMAC, to check
/// AWS-LC's against.
fn referencePrf(comptime Hmac: type, secret: []const u8, label: []const u8, seed1: []const u8, seed2: []const u8, out: []u8) void {
    // A(i) = HMAC(secret, A(i-1)), A(0) = seed;
    // P_hash = HMAC(secret, A(1) ‖ seed) ‖ HMAC(secret, A(2) ‖ seed) ‖ ...
    var a: [Hmac.mac_length]u8 = undefined;
    var m = Hmac.init(secret);
    m.update(label);
    m.update(seed1);
    m.update(seed2);
    m.final(&a);
    var n: usize = 0;
    while (n < out.len) {
        var block: [Hmac.mac_length]u8 = undefined;
        m = Hmac.init(secret);
        m.update(&a);
        m.update(label);
        m.update(seed1);
        m.update(seed2);
        m.final(&block);
        const take = @min(block.len, out.len - n);
        @memcpy(out[n..][0..take], block[0..take]);
        n += take;
        Hmac.create(&a, &a, secret);
    }
}

test "the PRF matches RFC 5246 written out, for both hashes" {
    const secret = "\x9b\xbe\x43\x6b\xa9\x40\xf0\x17\xb1\x76\x52\x84\x9a\x71\xdb\x35";
    const client_random: [32]u8 = @splat(0xa0);
    const server_random: [32]u8 = @splat(0x5b);
    // Lengths across block boundaries, the 12-byte verify_data and the
    // 48-byte master secret among them.
    for ([_]usize{ 1, 12, 31, 32, 33, 48, 72, 100, 136 }) |len| {
        var got: [136]u8 = undefined;
        var want: [136]u8 = undefined;
        tls12(.sha256, secret, "key expansion", &server_random, &client_random, got[0..len]);
        referencePrf(std.crypto.auth.hmac.sha2.HmacSha256, secret, "key expansion", &server_random, &client_random, want[0..len]);
        try testing.expectEqualSlices(u8, want[0..len], got[0..len]);

        tls12(.sha384, secret, "master secret", &client_random, &server_random, got[0..len]);
        referencePrf(std.crypto.auth.hmac.sha2.HmacSha384, secret, "master secret", &client_random, &server_random, want[0..len]);
        try testing.expectEqualSlices(u8, want[0..len], got[0..len]);
    }
}

test "the seed is the two parts joined" {
    var a: [48]u8 = undefined;
    var b: [48]u8 = undefined;
    tls12(.sha256, "secret", "extended master secret", "session hash", "", &a);
    tls12(.sha256, "secret", "extended master secret", "session ", "hash", &b);
    try testing.expectEqualSlices(u8, &a, &b);
    tls12(.sha256, "secret", "extended master secret", "session hash!", "", &b);
    try testing.expect(!std.mem.eql(u8, &a, &b));
}
