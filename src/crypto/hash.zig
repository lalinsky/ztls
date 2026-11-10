//! SHA-256 and SHA-384, the transcript hashes of the TLS 1.3 suites, and
//! HMAC over them for the Finished messages.

const std = @import("std");
const c = @import("c");

pub const Algorithm = enum {
    sha256,
    sha384,

    pub fn digestLength(a: Algorithm) usize {
        return switch (a) {
            .sha256 => Sha256.digest_length,
            .sha384 => Sha384.digest_length,
        };
    }

    pub fn md(a: Algorithm) *const c.EVP_MD {
        return switch (a) {
            .sha256 => c.EVP_sha256().?,
            .sha384 => c.EVP_sha384().?,
        };
    }
};

pub const max_digest_length = 48;

pub const Sha256 = Hash(.sha256);
pub const Sha384 = Hash(.sha384);

/// A running hash. The state is a plain struct with no pointers into itself,
/// so a copy is an independent fork of the hash: that is how `peek` works,
/// and how a handshake keeps hashing while it needs the hash so far.
pub fn Hash(comptime algorithm: Algorithm) type {
    return struct {
        ctx: Ctx,

        const Self = @This();
        const Ctx = switch (algorithm) {
            .sha256 => c.SHA256_CTX,
            .sha384 => c.SHA512_CTX,
        };

        pub const digest_length = switch (algorithm) {
            .sha256 => c.SHA256_DIGEST_LENGTH,
            .sha384 => c.SHA384_DIGEST_LENGTH,
        };
        pub const Digest = [digest_length]u8;

        pub fn init() Self {
            var self: Self = undefined;
            _ = switch (algorithm) {
                .sha256 => c.SHA256_Init(&self.ctx),
                .sha384 => c.SHA384_Init(&self.ctx),
            };
            return self;
        }

        pub fn update(self: *Self, data: []const u8) void {
            if (data.len == 0) return;
            _ = switch (algorithm) {
                .sha256 => c.SHA256_Update(&self.ctx, data.ptr, data.len),
                .sha384 => c.SHA384_Update(&self.ctx, data.ptr, data.len),
            };
        }

        /// Finishes the hash; `self` is not usable afterwards.
        pub fn final(self: *Self) Digest {
            var out: Digest = undefined;
            _ = switch (algorithm) {
                .sha256 => c.SHA256_Final(&out, &self.ctx),
                .sha384 => c.SHA384_Final(&out, &self.ctx),
            };
            self.* = undefined;
            return out;
        }

        /// The digest of everything hashed so far, leaving the hash running.
        pub fn peek(self: Self) Digest {
            var copy = self;
            return copy.final();
        }

        pub fn hash(data: []const u8) Digest {
            var h = init();
            h.update(data);
            return h.final();
        }
    };
}

/// HMAC with `algorithm` into `out`, returning the `digestLength` bytes used.
pub fn hmac(algorithm: Algorithm, key: []const u8, data: []const u8, out: *[max_digest_length]u8) []u8 {
    var out_len: c_uint = 0;
    const p = c.HMAC(algorithm.md(), key.ptr, key.len, data.ptr, data.len, out, &out_len);
    if (p == null or out_len != algorithm.digestLength()) @panic("HMAC failed");
    return out[0..out_len];
}

const testing = std.testing;

test "sha256 and sha384 one-shot" {
    try testing.expectEqualSlices(u8, &hex("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"), &Sha256.hash("abc"));
    try testing.expectEqualSlices(u8, &hex("cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7"), &Sha384.hash("abc"));
}

test "peek forks the running hash" {
    var h = Sha256.init();
    h.update("ab");
    const mid = h.peek();
    try testing.expectEqualSlices(u8, &Sha256.hash("ab"), &mid);
    h.update("c");
    try testing.expectEqualSlices(u8, &Sha256.hash("abc"), &h.final());
}

test "hmac" {
    // RFC 4231 test case 2.
    var buf: [max_digest_length]u8 = undefined;
    const mac = hmac(.sha256, "Jefe", "what do ya want for nothing?", &buf);
    try testing.expectEqualSlices(u8, &hex("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"), mac);
}

fn hex(comptime s: []const u8) [s.len / 2]u8 {
    var out: [s.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, s) catch unreachable;
    return out;
}
