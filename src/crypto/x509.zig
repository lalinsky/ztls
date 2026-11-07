//! Certificates, the trust store and chain verification through AWS-LC's
//! X.509 code. Only bytes go in: PEM is decoded here and DER parsed by
//! AWS-LC; reading files is the caller's job.

const std = @import("std");
const c = @import("c");
const err = @import("err.zig");
const pem = @import("pem.zig");
const sig = @import("sig.zig");

const log = std.log.scoped(.ztls);

pub const Certificate = struct {
    x509: *c.X509,

    pub fn parseDer(der: []const u8) error{InvalidCertificate}!Certificate {
        var p: [*c]const u8 = der.ptr;
        const x509 = c.d2i_X509(null, &p, @intCast(der.len)) orelse {
            _ = err.take();
            return error.InvalidCertificate;
        };
        if (p != der.ptr + der.len) {
            c.X509_free(x509);
            return error.InvalidCertificate;
        }
        return .{ .x509 = x509 };
    }

    /// The first CERTIFICATE block in `text`.
    pub fn parsePem(gpa: std.mem.Allocator, text: []const u8) (pem.Error || error{ InvalidCertificate, OutOfMemory })!Certificate {
        var it = pem.Iterator.init(text);
        while (try it.next()) |block| {
            if (!std.mem.eql(u8, block.label, "CERTIFICATE")) continue;
            const buf = try gpa.alloc(u8, block.decodedSizeUpperBound());
            defer gpa.free(buf);
            return parseDer(try block.decode(buf));
        }
        return error.InvalidCertificate;
    }

    pub fn deinit(self: *Certificate) void {
        c.X509_free(self.x509);
        self.* = undefined;
    }

    /// The subject's key, for verifying CertificateVerify.
    pub fn publicKey(self: *const Certificate) error{ UnsupportedKey, CryptoFailed }!sig.PublicKey {
        const pkey = c.X509_get_pubkey(self.x509) orelse return err.fail();
        return sig.PublicKey.fromPkey(pkey);
    }

    /// Whether `key` is the private half of the subject's key.
    pub fn matchesPrivateKey(self: *const Certificate, key: *const sig.PrivateKey) bool {
        if (c.X509_check_private_key(self.x509, key.pkey) == 1) return true;
        _ = err.take();
        return false;
    }
};

/// The certificate authorities a peer's chain must lead to. Built by the
/// caller and shared by any number of connections; verification only reads
/// it.
pub const TrustStore = struct {
    store: *c.X509_STORE,

    pub fn init() err.Error!TrustStore {
        const store = c.X509_STORE_new() orelse return err.fail();
        // Any certificate in the store is a trust anchor, including an
        // intermediate, as Go and std.crypto.Certificate.Bundle have it;
        // otherwise a chain would have to reach a self-signed root.
        if (c.X509_STORE_set_flags(store, c.X509_V_FLAG_PARTIAL_CHAIN) != 1) {
            c.X509_STORE_free(store);
            return err.fail();
        }
        return .{ .store = store };
    }

    pub fn deinit(self: *TrustStore) void {
        c.X509_STORE_free(self.store);
        self.* = undefined;
    }

    pub fn addDer(self: *TrustStore, der: []const u8) error{ InvalidCertificate, CryptoFailed }!void {
        var cert = try Certificate.parseDer(der);
        defer cert.deinit();
        try self.addCertificate(&cert);
    }

    /// Adds a copy of the certificate.
    pub fn addCertificate(self: *TrustStore, cert: *const Certificate) err.Error!void {
        if (c.X509_STORE_add_cert(self.store, cert.x509) != 1) return err.fail();
    }

    /// Adds every CERTIFICATE block in `text`; other blocks are ignored.
    /// Returns how many were added.
    pub fn addPem(self: *TrustStore, gpa: std.mem.Allocator, text: []const u8) (pem.Error || error{ InvalidCertificate, CryptoFailed, OutOfMemory })!usize {
        var count: usize = 0;
        var it = pem.Iterator.init(text);
        while (try it.next()) |block| {
            if (!std.mem.eql(u8, block.label, "CERTIFICATE")) continue;
            const buf = try gpa.alloc(u8, block.decodedSizeUpperBound());
            defer gpa.free(buf);
            try self.addDer(try block.decode(buf));
            count += 1;
        }
        return count;
    }
};

pub const Purpose = enum {
    /// The peer is a TLS server: id-kp-serverAuth.
    server,
    /// The peer is a TLS client: id-kp-clientAuth.
    client,
};

pub const VerifyOptions = struct {
    /// The time to validate at, in seconds since the Unix epoch.
    now: i64,
    purpose: Purpose,
    /// Checked against the leaf's DNS subject alternative names; the
    /// subject common name is never used.
    host: ?[]const u8 = null,
    /// A 4- or 16-byte address, checked against the leaf's IP subject
    /// alternative names.
    ip: ?[]const u8 = null,
};

/// Each name is a TLS alert, or the closest one.
pub const VerifyError = error{
    CertificateExpired,
    CertificateNotYetValid,
    /// The chain does not lead to a certificate in the store.
    UnknownCa,
    /// The leaf does not name the host or address.
    HostnameMismatch,
    /// Anything else: a bad signature, a broken chain, the wrong purpose.
    BadCertificate,
    CryptoFailed,
};

/// Verifies `chain`, leaf first, against the store. The rest of the chain
/// is untrusted: it only helps build a path to a trusted root.
pub fn verify(store: *const TrustStore, chain: []const Certificate, options: VerifyOptions) VerifyError!void {
    std.debug.assert(chain.len > 0);
    const ctx = c.X509_STORE_CTX_new() orelse return err.fail();
    defer c.X509_STORE_CTX_free(ctx);

    const untrusted = c.sk_X509_new_null() orelse return err.fail();
    defer c.sk_X509_free(untrusted); // holds no references of its own
    for (chain[1..]) |cert| {
        if (c.sk_X509_push(untrusted, cert.x509) == 0) return err.fail();
    }

    if (c.X509_STORE_CTX_init(ctx, store.store, chain[0].x509, untrusted) != 1) return err.fail();
    const param = c.X509_STORE_CTX_get0_param(ctx);
    c.X509_VERIFY_PARAM_set_time_posix(param, options.now);
    const purpose: c_int = switch (options.purpose) {
        .server => c.X509_PURPOSE_SSL_SERVER,
        .client => c.X509_PURPOSE_SSL_CLIENT,
    };
    if (c.X509_STORE_CTX_set_purpose(ctx, purpose) != 1) return err.fail();
    if (options.host) |host| {
        c.X509_VERIFY_PARAM_set_hostflags(param, c.X509_CHECK_FLAG_NEVER_CHECK_SUBJECT);
        if (c.X509_VERIFY_PARAM_set1_host(param, host.ptr, host.len) != 1) return err.fail();
    }
    if (options.ip) |ip| {
        if (c.X509_VERIFY_PARAM_set1_ip(param, ip.ptr, ip.len) != 1) return err.fail();
    }

    if (c.X509_verify_cert(ctx) == 1) return;
    const code = c.X509_STORE_CTX_get_error(ctx);
    _ = err.take();
    return switch (code) {
        c.X509_V_ERR_CERT_HAS_EXPIRED => error.CertificateExpired,
        c.X509_V_ERR_CERT_NOT_YET_VALID => error.CertificateNotYetValid,
        c.X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT,
        c.X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY,
        c.X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT,
        c.X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN,
        c.X509_V_ERR_CERT_UNTRUSTED,
        => error.UnknownCa,
        c.X509_V_ERR_HOSTNAME_MISMATCH, c.X509_V_ERR_IP_ADDRESS_MISMATCH => error.HostnameMismatch,
        else => {
            log.debug("certificate verification failed: {s}", .{c.X509_verify_cert_error_string(code)});
            return error.BadCertificate;
        },
    };
}

const testing = std.testing;

const pki = struct {
    const ca = @embedFile("../testdata/pki/ca.pem");
    const intermediate = @embedFile("../testdata/pki/intermediate.pem");
    const server_ec = @embedFile("../testdata/pki/server-ec.pem");
    const server_ec_key = @embedFile("../testdata/pki/server-ec.key");
    const server_rsa = @embedFile("../testdata/pki/server-rsa.pem");
    const server_ed25519 = @embedFile("../testdata/pki/server-ed25519.pem");
    const server_chain = @embedFile("../testdata/pki/server-chain.pem");
    const client = @embedFile("../testdata/pki/client.pem");
    const client_key = @embedFile("../testdata/pki/client.key");
    const selfsigned = @embedFile("../testdata/pki/selfsigned.pem");
};

/// Within the test PKI's validity (2027-01-15).
const valid_now: i64 = 1_800_000_000;

fn trustTestCa() !TrustStore {
    var store = try TrustStore.init();
    errdefer store.deinit();
    try testing.expectEqual(1, try store.addPem(testing.allocator, pki.ca));
    return store;
}

test "server certificates verify for their names" {
    var store = try trustTestCa();
    defer store.deinit();
    for ([_][]const u8{ pki.server_ec, pki.server_rsa, pki.server_ed25519 }) |text| {
        var cert = try Certificate.parsePem(testing.allocator, text);
        defer cert.deinit();
        const chain = [_]Certificate{cert};
        try verify(&store, &chain, .{ .now = valid_now, .purpose = .server, .host = "localhost" });
        try verify(&store, &chain, .{ .now = valid_now, .purpose = .server, .host = "LOCALHOST" });
        try verify(&store, &chain, .{ .now = valid_now, .purpose = .server, .host = "www.example.test" });
        try verify(&store, &chain, .{ .now = valid_now, .purpose = .server, .ip = &.{ 127, 0, 0, 1 } });
        var loopback6: [16]u8 = @splat(0);
        loopback6[15] = 1;
        try verify(&store, &chain, .{ .now = valid_now, .purpose = .server, .ip = &loopback6 });
        try verify(&store, &chain, .{ .now = valid_now, .purpose = .server });

        try testing.expectError(error.HostnameMismatch, verify(&store, &chain, .{ .now = valid_now, .purpose = .server, .host = "example.test" }));
        try testing.expectError(error.HostnameMismatch, verify(&store, &chain, .{ .now = valid_now, .purpose = .server, .host = "a.b.example.test" }));
        try testing.expectError(error.HostnameMismatch, verify(&store, &chain, .{ .now = valid_now, .purpose = .server, .host = "localhost.example.com" }));
        try testing.expectError(error.HostnameMismatch, verify(&store, &chain, .{ .now = valid_now, .purpose = .server, .ip = &.{ 10, 0, 0, 1 } }));
        try testing.expectError(error.CertificateNotYetValid, verify(&store, &chain, .{ .now = 1_000_000_000, .purpose = .server, .host = "localhost" }));
        try testing.expectError(error.CertificateExpired, verify(&store, &chain, .{ .now = 7_000_000_000, .purpose = .server, .host = "localhost" }));
        try testing.expectError(error.BadCertificate, verify(&store, &chain, .{ .now = valid_now, .purpose = .client }));
    }
}

test "a chain through an intermediate" {
    var store = try trustTestCa();
    defer store.deinit();
    // server-chain.pem holds the leaf and then the intermediate.
    var it = pem.Iterator.init(pki.server_chain);
    var chain: [2]Certificate = undefined;
    for (&chain) |*cert| {
        const block = (try it.next()).?;
        var buf: [2048]u8 = undefined;
        cert.* = try Certificate.parseDer(try block.decode(&buf));
    }
    defer for (&chain) |*cert| cert.deinit();

    try verify(&store, &chain, .{ .now = valid_now, .purpose = .server, .host = "localhost" });
    try testing.expectError(error.UnknownCa, verify(&store, chain[0..1], .{ .now = valid_now, .purpose = .server, .host = "localhost" }));

    // With the intermediate itself trusted, the leaf alone is enough.
    var store2 = try TrustStore.init();
    defer store2.deinit();
    _ = try store2.addPem(testing.allocator, pki.intermediate);
    try verify(&store2, chain[0..1], .{ .now = valid_now, .purpose = .server, .host = "localhost" });
}

test "untrusted and client certificates" {
    var store = try trustTestCa();
    defer store.deinit();

    var selfsigned = try Certificate.parsePem(testing.allocator, pki.selfsigned);
    defer selfsigned.deinit();
    try testing.expectError(error.UnknownCa, verify(&store, &.{selfsigned}, .{ .now = valid_now, .purpose = .server, .host = "localhost" }));

    var client = try Certificate.parsePem(testing.allocator, pki.client);
    defer client.deinit();
    try verify(&store, &.{client}, .{ .now = valid_now, .purpose = .client });
    try testing.expectError(error.BadCertificate, verify(&store, &.{client}, .{ .now = valid_now, .purpose = .server }));

    var empty = try TrustStore.init();
    defer empty.deinit();
    try testing.expectError(error.UnknownCa, verify(&empty, &.{client}, .{ .now = valid_now, .purpose = .client }));
}

test "public key and private key matching" {
    var cert = try Certificate.parsePem(testing.allocator, pki.server_ec);
    defer cert.deinit();
    var key = try sig.PrivateKey.parsePem(testing.allocator, pki.server_ec_key);
    defer key.deinit();
    var other = try sig.PrivateKey.parsePem(testing.allocator, pki.client_key);
    defer other.deinit();
    try testing.expect(cert.matchesPrivateKey(&key));
    try testing.expect(!cert.matchesPrivateKey(&other));

    var public = try cert.publicKey();
    defer public.deinit();
    try testing.expectEqual(sig.KeyType{ .ecdsa = .p256 }, public.key_type);
    var sig_buf: [128]u8 = undefined;
    const signature = try key.sign(.ecdsa_p256_sha256, "transcript", &sig_buf);
    try public.verify(.ecdsa_p256_sha256, "transcript", signature);
    try testing.expectError(error.SignatureInvalid, public.verify(.ecdsa_p256_sha256, "other", signature));
}

test "malformed certificates" {
    try testing.expectError(error.InvalidCertificate, Certificate.parseDer("not der"));
    try testing.expectError(error.InvalidCertificate, Certificate.parsePem(testing.allocator, pki.server_ec_key));
    var it = pem.Iterator.init(pki.ca);
    var buf: [2048]u8 = undefined;
    const der = try (try it.next()).?.decode(&buf);
    try testing.expectError(error.InvalidCertificate, Certificate.parseDer(der[0 .. der.len - 1]));
    buf[der.len] = 0;
    try testing.expectError(error.InvalidCertificate, Certificate.parseDer(buf[0 .. der.len + 1]));
}
