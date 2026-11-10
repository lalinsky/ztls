//! Key exchange for the TLS 1.3 key_share extension: X25519, ECDH on P-256
//! and P-384, ML-KEM-768, and the X25519MLKEM768 hybrid.
//!
//! Each key pair owns its secret and wipes it in `deinit`. Shared secrets
//! are returned by value: they go straight into the key schedule, whose
//! inputs the handshake wipes when it is done, and the stack copies made on
//! the way are accepted.

const std = @import("std");
const c = @import("c");
const err = @import("err.zig");

pub const X25519 = struct {
    pub const public_length = c.X25519_PUBLIC_VALUE_LEN;
    pub const secret_length = c.X25519_PRIVATE_KEY_LEN;
    pub const shared_length = c.X25519_SHARED_KEY_LEN;

    secret: [secret_length]u8,
    public: [public_length]u8,

    pub fn generate() X25519 {
        var kp: X25519 = undefined;
        c.X25519_keypair(&kp.public, &kp.secret);
        return kp;
    }

    pub fn fromSecret(secret: [secret_length]u8) X25519 {
        var kp: X25519 = .{ .secret = secret, .public = undefined };
        c.X25519_public_from_private(&kp.public, &kp.secret);
        return kp;
    }

    pub fn deinit(self: *X25519) void {
        std.crypto.secureZero(u8, &self.secret);
        self.* = undefined;
    }

    /// Fails on a peer value of small order (an all-zero result).
    pub fn sharedSecret(self: *const X25519, peer: *const [public_length]u8) error{InvalidPublicKey}![shared_length]u8 {
        var out: [shared_length]u8 = undefined;
        if (c.X25519(&out, &self.secret, peer) != 1) {
            _ = err.take();
            return error.InvalidPublicKey;
        }
        return out;
    }
};

/// ECDH on a NIST curve. The public value is the uncompressed point
/// (0x04 ‖ x ‖ y) and the shared secret is the x coordinate, as TLS wants.
pub const Ecdh = struct {
    pub const Curve = enum {
        p256,
        p384,

        fn nid(curve: Curve) c_int {
            return switch (curve) {
                .p256 => c.NID_X9_62_prime256v1,
                .p384 => c.NID_secp384r1,
            };
        }

        pub fn publicLength(curve: Curve) usize {
            return 1 + 2 * curve.sharedLength();
        }

        pub fn sharedLength(curve: Curve) usize {
            return switch (curve) {
                .p256 => 32,
                .p384 => 48,
            };
        }
    };

    pub const max_public_length = 97;
    pub const max_shared_length = 48;

    curve: Curve,
    key: *c.EC_KEY,

    pub fn generate(curve: Curve) err.Error!Ecdh {
        const key = c.EC_KEY_new_by_curve_name(curve.nid()) orelse return err.fail();
        errdefer c.EC_KEY_free(key);
        if (c.EC_KEY_generate_key(key) != 1) return err.fail();
        return .{ .curve = curve, .key = key };
    }

    pub fn deinit(self: *Ecdh) void {
        c.EC_KEY_free(self.key);
        self.* = undefined;
    }

    pub fn publicKey(self: *const Ecdh, out: *[max_public_length]u8) []u8 {
        const group = c.EC_KEY_get0_group(self.key);
        const point = c.EC_KEY_get0_public_key(self.key);
        const n = c.EC_POINT_point2oct(group, point, c.POINT_CONVERSION_UNCOMPRESSED, out, out.len, null);
        if (n != self.curve.publicLength()) @panic("EC_POINT_point2oct failed");
        return out[0..n];
    }

    pub fn sharedSecret(self: *const Ecdh, peer: []const u8, out: *[max_shared_length]u8) error{ InvalidPublicKey, CryptoFailed }![]u8 {
        const group = c.EC_KEY_get0_group(self.key);
        const point = c.EC_POINT_new(group) orelse return err.fail();
        defer c.EC_POINT_free(point);
        // Rejects points off the curve and compressed encodings.
        if (peer.len != self.curve.publicLength() or c.EC_POINT_oct2point(group, point, peer.ptr, peer.len, null) != 1) {
            _ = err.take();
            return error.InvalidPublicKey;
        }
        const len = self.curve.sharedLength();
        const n = c.ECDH_compute_key(out, len, point, self.key, null);
        if (n < 0 or @as(usize, @intCast(n)) != len) return err.fail();
        return out[0..len];
    }
};

pub const MlKem768 = struct {
    pub const public_key_length = 1184;
    pub const ciphertext_length = 1088;
    pub const shared_secret_length = 32;

    /// The key pair, kept in AWS-LC's object: the 2400-byte decapsulation
    /// key stays off the stack and is not re-imported for every use.
    pkey: *c.EVP_PKEY,
    public_key: [public_key_length]u8,

    pub fn generate() err.Error!MlKem768 {
        const ctx = c.EVP_PKEY_CTX_new_id(c.EVP_PKEY_KEM, null) orelse return err.fail();
        defer c.EVP_PKEY_CTX_free(ctx);
        if (c.EVP_PKEY_CTX_kem_set_params(ctx, c.NID_MLKEM768) != 1) return err.fail();
        if (c.EVP_PKEY_keygen_init(ctx) != 1) return err.fail();
        var pkey: ?*c.EVP_PKEY = null;
        if (c.EVP_PKEY_keygen(ctx, &pkey) != 1) return err.fail();
        errdefer c.EVP_PKEY_free(pkey);

        var kp: MlKem768 = .{ .pkey = pkey.?, .public_key = undefined };
        var len: usize = public_key_length;
        if (c.EVP_PKEY_get_raw_public_key(pkey, &kp.public_key, &len) != 1 or len != public_key_length) return err.fail();
        return kp;
    }

    /// Frees the key pair; AWS-LC wipes the secret.
    pub fn deinit(self: *MlKem768) void {
        c.EVP_PKEY_free(self.pkey);
        self.* = undefined;
    }

    pub const Encapsulation = struct {
        ciphertext: [ciphertext_length]u8,
        shared_secret: [shared_secret_length]u8,
    };

    /// The sender's side: a fresh shared secret, encapsulated to `public_key`.
    /// Fails on an encapsulation key that does not pass FIPS 203's check.
    pub fn encapsulate(public_key: *const [public_key_length]u8) error{ InvalidPublicKey, CryptoFailed }!Encapsulation {
        const pkey = c.EVP_PKEY_kem_new_raw_public_key(c.NID_MLKEM768, public_key, public_key_length) orelse {
            _ = err.take();
            return error.InvalidPublicKey;
        };
        defer c.EVP_PKEY_free(pkey);
        const ctx = c.EVP_PKEY_CTX_new(pkey, null) orelse return err.fail();
        defer c.EVP_PKEY_CTX_free(ctx);

        var e: Encapsulation = undefined;
        var ct_len: usize = ciphertext_length;
        var ss_len: usize = shared_secret_length;
        if (c.EVP_PKEY_encapsulate(ctx, &e.ciphertext, &ct_len, &e.shared_secret, &ss_len) != 1) {
            _ = err.take();
            return error.InvalidPublicKey;
        }
        if (ct_len != ciphertext_length or ss_len != shared_secret_length) return error.CryptoFailed;
        return e;
    }

    /// Never fails on a malformed ciphertext: ML-KEM then yields an
    /// unrelated secret (implicit rejection), and the handshake fails later.
    pub fn decapsulate(self: *const MlKem768, ciphertext: *const [ciphertext_length]u8) err.Error![shared_secret_length]u8 {
        const ctx = c.EVP_PKEY_CTX_new(self.pkey, null) orelse return err.fail();
        defer c.EVP_PKEY_CTX_free(ctx);

        var ss: [shared_secret_length]u8 = undefined;
        var ss_len: usize = shared_secret_length;
        if (c.EVP_PKEY_decapsulate(ctx, &ss, &ss_len, ciphertext, ciphertext_length) != 1) return err.fail();
        if (ss_len != shared_secret_length) return error.CryptoFailed;
        return ss;
    }
};

/// X25519MLKEM768 (draft-ietf-tls-ecdhe-mlkem): the client share is the
/// ML-KEM encapsulation key followed by the X25519 value, the server share
/// the ML-KEM ciphertext followed by the X25519 value, and the shared secret
/// the ML-KEM secret followed by the X25519 secret.
pub const X25519MlKem768 = struct {
    pub const client_share_length = MlKem768.public_key_length + X25519.public_length; // 1216
    pub const server_share_length = MlKem768.ciphertext_length + X25519.public_length; // 1120
    pub const shared_secret_length = MlKem768.shared_secret_length + X25519.shared_length; // 64

    kem: MlKem768,
    x25519: X25519,

    pub fn generate() err.Error!X25519MlKem768 {
        return .{ .kem = try MlKem768.generate(), .x25519 = X25519.generate() };
    }

    pub fn deinit(self: *X25519MlKem768) void {
        self.kem.deinit();
        self.x25519.deinit();
    }

    pub fn clientShare(self: *const X25519MlKem768) [client_share_length]u8 {
        return self.kem.public_key ++ self.x25519.public;
    }

    /// The server's side, from the client's share: the server share to send
    /// back and the shared secret. Needs no key pair of its own.
    pub fn respond(client_share: *const [client_share_length]u8, out_server_share: *[server_share_length]u8) error{ InvalidPublicKey, CryptoFailed }![shared_secret_length]u8 {
        const e = try MlKem768.encapsulate(client_share[0..MlKem768.public_key_length]);
        var x = X25519.generate();
        defer x.deinit();
        const xs = try x.sharedSecret(client_share[MlKem768.public_key_length..][0..X25519.public_length]);
        out_server_share.* = e.ciphertext ++ x.public;
        return e.shared_secret ++ xs;
    }

    /// The client's side, from the server's share.
    pub fn finish(self: *const X25519MlKem768, server_share: *const [server_share_length]u8) error{ InvalidPublicKey, CryptoFailed }![shared_secret_length]u8 {
        const ks = try self.kem.decapsulate(server_share[0..MlKem768.ciphertext_length]);
        const xs = try self.x25519.sharedSecret(server_share[MlKem768.ciphertext_length..][0..X25519.public_length]);
        return ks ++ xs;
    }
};

const testing = std.testing;
const data13 = @import("../testdata/tls13.zig");

test "x25519 against the example connection" {
    var kp = X25519.fromSecret(data13.client_private_key);
    defer kp.deinit();
    try testing.expectEqualSlices(u8, &data13.client_public_key, &kp.public);
    try testing.expectEqualSlices(u8, &data13.shared_key, &try kp.sharedSecret(&data13.server_pub_key));
}

test "x25519 agreement and small-order rejection" {
    var a = X25519.generate();
    defer a.deinit();
    var b = X25519.generate();
    defer b.deinit();
    try testing.expectEqualSlices(u8, &try a.sharedSecret(&b.public), &try b.sharedSecret(&a.public));
    try testing.expectError(error.InvalidPublicKey, a.sharedSecret(&@as([32]u8, @splat(0))));
}

test "ecdh agreement and invalid point rejection" {
    for ([_]Ecdh.Curve{ .p256, .p384 }) |curve| {
        var a = try Ecdh.generate(curve);
        defer a.deinit();
        var b = try Ecdh.generate(curve);
        defer b.deinit();
        var a_pub: [Ecdh.max_public_length]u8 = undefined;
        var b_pub: [Ecdh.max_public_length]u8 = undefined;
        const a_public = a.publicKey(&a_pub);
        const b_public = b.publicKey(&b_pub);
        try testing.expectEqual(curve.publicLength(), a_public.len);
        try testing.expectEqual(0x04, a_public[0]);

        var s1: [Ecdh.max_shared_length]u8 = undefined;
        var s2: [Ecdh.max_shared_length]u8 = undefined;
        const ab = try a.sharedSecret(b_public, &s1);
        const ba = try b.sharedSecret(a_public, &s2);
        try testing.expectEqual(curve.sharedLength(), ab.len);
        try testing.expectEqualSlices(u8, ab, ba);

        // Off the curve.
        var bad: [Ecdh.max_public_length]u8 = b_pub;
        bad[1] ^= 1;
        try testing.expectError(error.InvalidPublicKey, a.sharedSecret(bad[0..b_public.len], &s1));
        // Wrong length.
        try testing.expectError(error.InvalidPublicKey, a.sharedSecret(b_public[0 .. b_public.len - 1], &s1));
        // Point at infinity.
        try testing.expectError(error.InvalidPublicKey, a.sharedSecret(&[_]u8{0}, &s1));
    }
}

test "ml-kem-768 agreement and implicit rejection" {
    var kp = try MlKem768.generate();
    defer kp.deinit();
    const e = try MlKem768.encapsulate(&kp.public_key);
    try testing.expectEqualSlices(u8, &e.shared_secret, &try kp.decapsulate(&e.ciphertext));

    var tampered = e.ciphertext;
    tampered[0] ^= 1;
    try testing.expect(!std.mem.eql(u8, &e.shared_secret, &try kp.decapsulate(&tampered)));
}

test "x25519mlkem768 agreement" {
    var client = try X25519MlKem768.generate();
    defer client.deinit();
    const client_share = client.clientShare();
    var server_share: [X25519MlKem768.server_share_length]u8 = undefined;
    const server_secret = try X25519MlKem768.respond(&client_share, &server_share);
    const client_secret = try client.finish(&server_share);
    try testing.expectEqualSlices(u8, &server_secret, &client_secret);
}
