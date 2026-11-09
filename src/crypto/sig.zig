//! Private and public keys for CertificateVerify and the TLS 1.2
//! ServerKeyExchange: ECDSA, RSA-PSS, RSA PKCS#1 v1.5 and Ed25519 through
//! AWS-LC's EVP interface, with each signature algorithm tied to the keys
//! it is defined for.

const std = @import("std");
const assert = std.debug.assert;
const c = @import("c");
const err = @import("err.zig");
const pem = @import("pem.zig");

/// The signature algorithms a handshake signs with: those of RFC 9846
/// §4.3.3 that may sign a TLS 1.3 CertificateVerify, and the TLS 1.2-only
/// ones below them. In TLS 1.3 the rsa_pkcs1 schemes appear only in
/// certificates, where X.509 verification handles them.
pub const Algorithm = enum {
    ecdsa_p256_sha256,
    ecdsa_p384_sha384,
    ecdsa_p521_sha512,
    rsa_pss_sha256,
    rsa_pss_sha384,
    rsa_pss_sha512,
    ed25519,

    // TLS 1.2 only (RFC 5246 §7.4.1.4.1, RFC 8422 §5.1.1): RSA PKCS#1 v1.5,
    // and ECDSA with the hash alone named, on whatever curve the key is.
    rsa_pkcs1_sha256,
    rsa_pkcs1_sha384,
    rsa_pkcs1_sha512,
    ecdsa_sha256,
    ecdsa_sha384,
    ecdsa_sha512,

    fn md(a: Algorithm) ?*const c.EVP_MD {
        return switch (a) {
            .ecdsa_p256_sha256, .rsa_pss_sha256, .rsa_pkcs1_sha256, .ecdsa_sha256 => c.EVP_sha256(),
            .ecdsa_p384_sha384, .rsa_pss_sha384, .rsa_pkcs1_sha384, .ecdsa_sha384 => c.EVP_sha384(),
            .ecdsa_p521_sha512, .rsa_pss_sha512, .rsa_pkcs1_sha512, .ecdsa_sha512 => c.EVP_sha512(),
            .ed25519 => null,
        };
    }

    fn isRsaPss(a: Algorithm) bool {
        return switch (a) {
            .rsa_pss_sha256, .rsa_pss_sha384, .rsa_pss_sha512 => true,
            else => false,
        };
    }

    /// Whether a key of this type may sign or verify with the algorithm.
    pub fn suits(a: Algorithm, key_type: KeyType) bool {
        return switch (a) {
            .ecdsa_p256_sha256 => key_type == .ecdsa and key_type.ecdsa == .p256,
            .ecdsa_p384_sha384 => key_type == .ecdsa and key_type.ecdsa == .p384,
            .ecdsa_p521_sha512 => key_type == .ecdsa and key_type.ecdsa == .p521,
            .rsa_pss_sha256, .rsa_pss_sha384, .rsa_pss_sha512 => key_type == .rsa,
            .ed25519 => key_type == .ed25519,
            .rsa_pkcs1_sha256, .rsa_pkcs1_sha384, .rsa_pkcs1_sha512 => key_type == .rsa,
            .ecdsa_sha256, .ecdsa_sha384, .ecdsa_sha512 => key_type == .ecdsa,
        };
    }
};

pub const Curve = enum { p256, p384, p521 };

pub const KeyType = union(enum) {
    /// Modulus size in bits.
    rsa: u32,
    ecdsa: Curve,
    ed25519,
};

/// Smaller RSA keys are refused, ours and the peer's alike.
pub const min_rsa_bits = 2048;

fn keyTypeOf(pkey: *c.EVP_PKEY) error{UnsupportedKey}!KeyType {
    return switch (c.EVP_PKEY_id(pkey)) {
        c.EVP_PKEY_RSA => {
            const bits: u32 = @intCast(c.EVP_PKEY_bits(pkey));
            if (bits < min_rsa_bits) return error.UnsupportedKey;
            return .{ .rsa = bits };
        },
        c.EVP_PKEY_EC => {
            const group = c.EC_KEY_get0_group(c.EVP_PKEY_get0_EC_KEY(pkey));
            return switch (c.EC_GROUP_get_curve_name(group)) {
                c.NID_X9_62_prime256v1 => .{ .ecdsa = .p256 },
                c.NID_secp384r1 => .{ .ecdsa = .p384 },
                c.NID_secp521r1 => .{ .ecdsa = .p521 },
                else => error.UnsupportedKey,
            };
        },
        c.EVP_PKEY_ED25519 => .ed25519,
        else => error.UnsupportedKey,
    };
}

pub const ParseError = error{ InvalidKey, UnsupportedKey, CryptoFailed, OutOfMemory } || pem.Error;

pub const PrivateKey = struct {
    pkey: *c.EVP_PKEY,
    key_type: KeyType,

    pub const Format = enum {
        /// PKCS#8 PrivateKeyInfo, "BEGIN PRIVATE KEY".
        pkcs8,
        /// SEC 1 ECPrivateKey, "BEGIN EC PRIVATE KEY".
        sec1,
        /// PKCS#1 RSAPrivateKey, "BEGIN RSA PRIVATE KEY".
        pkcs1,

        fn fromLabel(label: []const u8) ?Format {
            if (std.mem.eql(u8, label, "PRIVATE KEY")) return .pkcs8;
            if (std.mem.eql(u8, label, "EC PRIVATE KEY")) return .sec1;
            if (std.mem.eql(u8, label, "RSA PRIVATE KEY")) return .pkcs1;
            return null;
        }
    };

    /// The first private key block in `text`. Encrypted keys are not
    /// supported. The decoded DER passes through `gpa` and is wiped.
    pub fn parsePem(gpa: std.mem.Allocator, text: []const u8) ParseError!PrivateKey {
        var it = pem.Iterator.init(text);
        while (try it.next()) |block| {
            const format = Format.fromLabel(block.label) orelse continue;
            const buf = try gpa.alloc(u8, block.decodedSizeUpperBound());
            defer {
                std.crypto.secureZero(u8, buf);
                gpa.free(buf);
            }
            const der = try block.decode(buf);
            return parseDer(format, der);
        }
        return error.InvalidKey;
    }

    pub fn parseDer(format: Format, der: []const u8) ParseError!PrivateKey {
        var cbs: c.CBS = undefined;
        c.CBS_init(&cbs, der.ptr, der.len);
        const pkey: *c.EVP_PKEY = switch (format) {
            .pkcs8 => c.EVP_parse_private_key(&cbs) orelse return invalid(),
            .sec1 => blk: {
                const ec = c.EC_KEY_parse_private_key(&cbs, null) orelse return invalid();
                const pkey = c.EVP_PKEY_new() orelse {
                    c.EC_KEY_free(ec);
                    return err.fail();
                };
                if (c.EVP_PKEY_assign_EC_KEY(pkey, ec) != 1) {
                    c.EC_KEY_free(ec);
                    c.EVP_PKEY_free(pkey);
                    return err.fail();
                }
                break :blk pkey;
            },
            .pkcs1 => blk: {
                const rsa = c.RSA_parse_private_key(&cbs) orelse return invalid();
                const pkey = c.EVP_PKEY_new() orelse {
                    c.RSA_free(rsa);
                    return err.fail();
                };
                if (c.EVP_PKEY_assign_RSA(pkey, rsa) != 1) {
                    c.RSA_free(rsa);
                    c.EVP_PKEY_free(pkey);
                    return err.fail();
                }
                break :blk pkey;
            },
        };
        errdefer c.EVP_PKEY_free(pkey);
        if (c.CBS_len(&cbs) != 0) return error.InvalidKey;
        return .{ .pkey = pkey, .key_type = try keyTypeOf(pkey) };
    }

    fn invalid() ParseError {
        _ = err.take();
        return error.InvalidKey;
    }

    /// Frees the key; AWS-LC wipes it.
    pub fn deinit(self: *PrivateKey) void {
        c.EVP_PKEY_free(self.pkey);
        self.* = undefined;
    }

    /// Room a signature needs.
    pub fn maxSignatureLength(self: *const PrivateKey) usize {
        return @intCast(c.EVP_PKEY_size(self.pkey));
    }

    /// Signs `message` into `out`, returning the signature. Fails with
    /// `AlgorithmMismatch` unless `algorithm.suits(self.key_type)`.
    pub fn sign(self: *const PrivateKey, algorithm: Algorithm, message: []const u8, out: []u8) error{ AlgorithmMismatch, CryptoFailed }![]u8 {
        if (!algorithm.suits(self.key_type)) return error.AlgorithmMismatch;
        var md_ctx: c.EVP_MD_CTX = undefined;
        c.EVP_MD_CTX_init(&md_ctx);
        defer _ = c.EVP_MD_CTX_cleanup(&md_ctx);
        var pctx: ?*c.EVP_PKEY_CTX = null;
        if (c.EVP_DigestSignInit(&md_ctx, &pctx, algorithm.md(), null, self.pkey) != 1) return err.fail();
        try setPss(pctx, algorithm);
        var sig_len: usize = out.len;
        if (c.EVP_DigestSign(&md_ctx, out.ptr, &sig_len, message.ptr, message.len) != 1) return err.fail();
        return out[0..sig_len];
    }
};

pub const PublicKey = struct {
    pkey: *c.EVP_PKEY,
    key_type: KeyType,

    /// Takes ownership of `pkey`.
    pub fn fromPkey(pkey: *c.EVP_PKEY) error{UnsupportedKey}!PublicKey {
        errdefer c.EVP_PKEY_free(pkey);
        return .{ .pkey = pkey, .key_type = try keyTypeOf(pkey) };
    }

    pub fn deinit(self: *PublicKey) void {
        c.EVP_PKEY_free(self.pkey);
        self.* = undefined;
    }

    /// Fails with `AlgorithmMismatch` unless `algorithm.suits(self.key_type)`:
    /// TLS 1.3 ties each ECDSA curve to one hash, TLS 1.2 does not.
    pub fn verify(self: *const PublicKey, algorithm: Algorithm, message: []const u8, signature: []const u8) error{ SignatureInvalid, AlgorithmMismatch, CryptoFailed }!void {
        if (!algorithm.suits(self.key_type)) return error.AlgorithmMismatch;
        var md_ctx: c.EVP_MD_CTX = undefined;
        c.EVP_MD_CTX_init(&md_ctx);
        defer _ = c.EVP_MD_CTX_cleanup(&md_ctx);
        var pctx: ?*c.EVP_PKEY_CTX = null;
        if (c.EVP_DigestVerifyInit(&md_ctx, &pctx, algorithm.md(), null, self.pkey) != 1) return err.fail();
        try setPss(pctx, algorithm);
        if (c.EVP_DigestVerify(&md_ctx, signature.ptr, signature.len, message.ptr, message.len) != 1) {
            _ = err.take();
            return error.SignatureInvalid;
        }
    }
};

/// RSA-PSS as TLS 1.3 wants it: MGF1 with the same hash (AWS-LC's default)
/// and a salt as long as the digest. PKCS#1 v1.5 is AWS-LC's default
/// padding for RSA keys and needs nothing.
fn setPss(pctx: ?*c.EVP_PKEY_CTX, algorithm: Algorithm) err.Error!void {
    if (!algorithm.isRsaPss()) return;
    if (c.EVP_PKEY_CTX_set_rsa_padding(pctx, c.RSA_PKCS1_PSS_PADDING) != 1) return err.fail();
    if (c.EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, c.RSA_PSS_SALTLEN_DIGEST) != 1) return err.fail();
}

const testing = std.testing;

const test_keys = [_]struct { pem: []const u8, key_type: KeyType, algorithm: Algorithm }{
    .{ .pem = @embedFile("../testdata/keys/ec_prime256v1_private_key.pem"), .key_type = .{ .ecdsa = .p256 }, .algorithm = .ecdsa_p256_sha256 },
    .{ .pem = @embedFile("../testdata/keys/ec_private_key.pem"), .key_type = .{ .ecdsa = .p384 }, .algorithm = .ecdsa_p384_sha384 },
    .{ .pem = @embedFile("../testdata/keys/ec_secp384r1_private_key.pem"), .key_type = .{ .ecdsa = .p384 }, .algorithm = .ecdsa_p384_sha384 },
    .{ .pem = @embedFile("../testdata/keys/ed25519_private_key.pem"), .key_type = .ed25519, .algorithm = .ed25519 },
    .{ .pem = @embedFile("../testdata/keys/rsa_private_key.pem"), .key_type = .{ .rsa = 2048 }, .algorithm = .rsa_pss_sha256 },
    .{ .pem = @embedFile("../testdata/pki/server-rsa.key"), .key_type = .{ .rsa = 2048 }, .algorithm = .rsa_pss_sha384 },
    .{ .pem = @embedFile("../testdata/pki/server-chain.key"), .key_type = .{ .ecdsa = .p384 }, .algorithm = .ecdsa_p384_sha384 },
};

/// The public half of a private key, as a verifier would hold it.
fn publicOf(key: *const PrivateKey) !PublicKey {
    // Round-trip through DER SubjectPublicKeyInfo.
    var der: [*c]u8 = null;
    const len = c.i2d_PUBKEY(key.pkey, &der);
    if (len <= 0) return error.CryptoFailed;
    defer c.OPENSSL_free(der);
    var p: [*c]const u8 = der;
    const pkey = c.d2i_PUBKEY(null, &p, len) orelse return error.CryptoFailed;
    return PublicKey.fromPkey(pkey);
}

test "parse, sign and verify with every test key" {
    for (test_keys) |tk| {
        var key = try PrivateKey.parsePem(testing.allocator, tk.pem);
        defer key.deinit();
        try testing.expectEqual(tk.key_type, key.key_type);

        var sig_buf: [512]u8 = undefined;
        try testing.expect(key.maxSignatureLength() <= sig_buf.len);
        const message = "CertificateVerify content";
        const signature = try key.sign(tk.algorithm, message, &sig_buf);

        var public = try publicOf(&key);
        defer public.deinit();
        try testing.expectEqual(tk.key_type, public.key_type);
        try public.verify(tk.algorithm, message, signature);
        try testing.expectError(error.SignatureInvalid, public.verify(tk.algorithm, "other message", signature));
        var bad = sig_buf;
        bad[signature.len / 2] ^= 1;
        try testing.expectError(error.SignatureInvalid, public.verify(tk.algorithm, message, bad[0..signature.len]));
    }
}

test "an algorithm must suit the key" {
    var p256 = try PrivateKey.parsePem(testing.allocator, test_keys[0].pem);
    defer p256.deinit();
    var p384 = try PrivateKey.parsePem(testing.allocator, test_keys[1].pem);
    defer p384.deinit();
    var sig_buf: [512]u8 = undefined;
    try testing.expectError(error.AlgorithmMismatch, p256.sign(.ecdsa_p384_sha384, "m", &sig_buf));
    try testing.expectError(error.AlgorithmMismatch, p256.sign(.rsa_pss_sha256, "m", &sig_buf));
    try testing.expectError(error.AlgorithmMismatch, p384.sign(.ed25519, "m", &sig_buf));

    const signature = try p256.sign(.ecdsa_p256_sha256, "m", &sig_buf);
    var public = try publicOf(&p384);
    defer public.deinit();
    try testing.expectError(error.AlgorithmMismatch, public.verify(.ecdsa_p256_sha256, "m", signature));
}

test "TLS 1.2 algorithms: PKCS#1 v1.5, and ECDSA on any curve" {
    var rsa = try PrivateKey.parsePem(testing.allocator, test_keys[4].pem);
    defer rsa.deinit();
    var rsa_public = try publicOf(&rsa);
    defer rsa_public.deinit();
    var sig_buf: [512]u8 = undefined;
    for ([_]Algorithm{ .rsa_pkcs1_sha256, .rsa_pkcs1_sha384, .rsa_pkcs1_sha512 }) |algorithm| {
        const signature = try rsa.sign(algorithm, "ServerKeyExchange", &sig_buf);
        try rsa_public.verify(algorithm, "ServerKeyExchange", signature);
        try testing.expectError(error.SignatureInvalid, rsa_public.verify(algorithm, "other", signature));
        // PKCS#1 v1.5 and PSS are not interchangeable.
        try testing.expectError(error.SignatureInvalid, rsa_public.verify(.rsa_pss_sha256, "ServerKeyExchange", signature));
    }
    // PKCS#1 v1.5 is deterministic: the same message, the same signature.
    const a = try rsa.sign(.rsa_pkcs1_sha256, "m", &sig_buf);
    var other_buf: [512]u8 = undefined;
    const b = try rsa.sign(.rsa_pkcs1_sha256, "m", &other_buf);
    try testing.expectEqualSlices(u8, a, b);

    // A P-384 key signs with SHA-256 in TLS 1.2, which TLS 1.3 forbids.
    var p384 = try PrivateKey.parsePem(testing.allocator, test_keys[1].pem);
    defer p384.deinit();
    var p384_public = try publicOf(&p384);
    defer p384_public.deinit();
    for ([_]Algorithm{ .ecdsa_sha256, .ecdsa_sha384, .ecdsa_sha512 }) |algorithm| {
        const signature = try p384.sign(algorithm, "ServerKeyExchange", &sig_buf);
        try p384_public.verify(algorithm, "ServerKeyExchange", signature);
    }
    try testing.expectError(error.AlgorithmMismatch, p384.sign(.ecdsa_p256_sha256, "m", &sig_buf));

    // Each still needs its kind of key.
    try testing.expectError(error.AlgorithmMismatch, rsa.sign(.ecdsa_sha256, "m", &sig_buf));
    try testing.expectError(error.AlgorithmMismatch, p384.sign(.rsa_pkcs1_sha256, "m", &sig_buf));
    var ed = try PrivateKey.parsePem(testing.allocator, test_keys[3].pem);
    defer ed.deinit();
    try testing.expectError(error.AlgorithmMismatch, ed.sign(.ecdsa_sha256, "m", &sig_buf));
}

test "ed25519 signatures verify with std.crypto" {
    var key = try PrivateKey.parsePem(testing.allocator, test_keys[3].pem);
    defer key.deinit();
    var raw: [32]u8 = undefined;
    var raw_len: usize = raw.len;
    try testing.expectEqual(1, c.EVP_PKEY_get_raw_public_key(key.pkey, &raw, &raw_len));
    const public = try std.crypto.sign.Ed25519.PublicKey.fromBytes(raw);

    var sig_buf: [64]u8 = undefined;
    const signature = try key.sign(.ed25519, "hello", &sig_buf);
    try std.crypto.sign.Ed25519.Signature.fromBytes(signature[0..64].*).verify("hello", public);
}

test "malformed and unsupported keys" {
    try testing.expectError(error.UnsupportedKey, PrivateKey.parsePem(testing.allocator, @embedFile("../testdata/keys/rsa_1024_private_key.pem")));
    try testing.expectError(error.InvalidKey, PrivateKey.parsePem(testing.allocator, "nothing here"));
    try testing.expectError(error.InvalidKey, PrivateKey.parsePem(testing.allocator, "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n"));
    try testing.expectError(error.InvalidPem, PrivateKey.parsePem(testing.allocator, "-----BEGIN PRIVATE KEY-----\nAAAA\n"));
    // Trailing garbage after the DER.
    var it = pem.Iterator.init(test_keys[0].pem);
    const block = (try it.next()).?;
    var buf: [256]u8 = undefined;
    const der = try block.decode(&buf);
    buf[der.len] = 0;
    try testing.expectError(error.InvalidKey, PrivateKey.parseDer(.sec1, buf[0 .. der.len + 1]));
    try testing.expectError(error.InvalidKey, PrivateKey.parseDer(.pkcs8, der));
}
