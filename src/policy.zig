//! The rules both implementations apply, so that they agree: which
//! options are refused, which signature schemes a key may sign with, and
//! how a peer's certificate chain is verified.

const std = @import("std");
const proto = @import("protocol.zig");
const config = @import("config.zig");
const crypto = @import("crypto.zig");
const api = @import("api.zig");
const sig = crypto.sig;
const x509 = crypto.x509;

/// The protocol version a rule is applied for.
pub const Version = enum { tls13, tls12 };

/// Refuses client options that make no sense, before anything is sent.
pub fn checkClient(opt: config.Client) error{TlsInternalError}!void {
    if (opt.root_ca == null and !opt.insecure_skip_verify) return error.TlsInternalError;
    if (opt.host.len == 0 and !opt.insecure_skip_verify) return error.TlsInternalError;
    if (opt.host.len > 255) return error.TlsInternalError;
    // AWS-LC would match any subdomain of a name that starts with a dot.
    if (opt.host.len > 0 and opt.host[0] == '.') return error.TlsInternalError;
    for (opt.named_groups) |group| {
        if (groupKnown(group)) break;
    } else return error.TlsInternalError;
    if (opt.verify_schemes.len == 0) return error.TlsInternalError;
    if (!schemesSupported(opt.verify_schemes) or !schemesSupported(opt.signing_schemes)) return error.TlsInternalError;
    if (!offers(opt, .tls_1_3) and !offers(opt, .tls_1_2)) return error.TlsInternalError;
    if (offers(opt, .tls_1_3)) {
        if (opt.key_shares.len == 0) return error.TlsInternalError;
        for (opt.key_shares, 0..) |group, i| {
            if (std.mem.indexOfScalar(proto.NamedGroup, opt.named_groups, group) == null) return error.TlsInternalError;
            // One share per group (§4.2.8).
            if (std.mem.indexOfScalar(proto.NamedGroup, opt.key_shares[0..i], group) != null) return error.TlsInternalError;
        }
    }
}

/// The suites a client offers: the default list puts ChaCha20-Poly1305
/// first without AES instructions, where software AES is several times
/// slower, so that servers that follow the client's order pick it. Any
/// other list is offered as given.
pub fn offeredSuites(suites: []const proto.CipherSuite, aes_hardware: bool) []const proto.CipherSuite {
    if (aes_hardware or !std.mem.eql(proto.CipherSuite, suites, &config.default_cipher_suites)) return suites;
    return &config.default_cipher_suites_chacha_first;
}

/// The server's TLS 1.3 suite: the first of ours, TLS 1.2 ones passed
/// over, that the client offers. `offered` is the ClientHello's
/// cipher_suites as sent, two bytes each.
pub fn chooseSuite(ours: []const proto.CipherSuite, offered: []const u8, aes_hardware: bool) ?proto.CipherSuite {
    const first = for (0..offered.len / 2) |i| {
        const suite = suiteAt(offered, i);
        if (suite.version() == .tls_1_3) break suite;
    } else null;
    for (preferredSuites(ours, aes_hardware, first)) |suite| {
        if (suite.version() != .tls_1_3) continue;
        for (0..offered.len / 2) |i| {
            if (suiteAt(offered, i) == suite) return suite;
        }
    }
    return null;
}

fn suiteAt(offered: []const u8, i: usize) proto.CipherSuite {
    return @enumFromInt(std.mem.readInt(u16, offered[2 * i ..][0..2], .big));
}

/// Our suites in preference order: the default list prefers
/// ChaCha20-Poly1305 when either side lacks AES instructions, ours or the
/// client's, which it tells by listing ChaCha20 first, as Go and BoringSSL
/// servers have it. Any other list is followed as given.
fn preferredSuites(suites: []const proto.CipherSuite, aes_hardware: bool, client_first: ?proto.CipherSuite) []const proto.CipherSuite {
    if (!std.mem.eql(proto.CipherSuite, suites, &proto.CipherSuite.all)) return suites;
    if (aes_hardware and client_first != .chacha20_poly1305_sha256) return suites;
    return &config.default_server_cipher_suites_chacha_first;
}

/// Whether `cipher_suites` offers `version`: it does with any of its
/// suites.
pub fn offers(opt: config.Client, comptime version: proto.Version) bool {
    for (opt.cipher_suites) |suite| {
        if (suite.version() == version) return true;
    }
    return false;
}

/// Whether `host` is an IP literal, which gets no SNI (RFC 6066 §3).
fn isIpLiteral(host: []const u8) bool {
    _ = std.Io.net.IpAddress.parse(host, 0) catch return false;
    return true;
}

/// Whether `host` goes out as SNI: a non-empty name that is not an
/// IP literal.
pub fn sendsSni(host: []const u8) bool {
    return host.len != 0 and !isIpLiteral(host);
}

/// Refuses server options that make no sense, before anything is read.
pub fn checkServer(opt: config.Server) error{TlsInternalError}!void {
    if (opt.verify_schemes.len == 0 or opt.signing_schemes.len == 0) return error.TlsInternalError;
    for (opt.named_groups) |group| {
        if (groupKnown(group)) break;
    } else return error.TlsInternalError;
    // The server speaks TLS 1.3 only, so it needs one of its suites.
    for (opt.cipher_suites) |suite| {
        if (suite.version() == .tls_1_3) break;
    } else return error.TlsInternalError;
    if (!schemesSupported(opt.verify_schemes) or !schemesSupported(opt.signing_schemes)) return error.TlsInternalError;
}

/// Whether `group` is one ztls has a key exchange for in either
/// implementation; not every implementation has every one.
pub fn groupKnown(group: proto.NamedGroup) bool {
    return switch (group) {
        .x25519_ml_kem768, .x25519, .secp256r1, .secp384r1, .secp521r1 => true,
        else => false,
    };
}

/// The algorithm a scheme stands for when it signs a handshake in
/// `version`: a CertificateVerify, or in TLS 1.2 a ServerKeyExchange too.
/// Null for one that may not: the rsa_pkcs1 ones in TLS 1.3 (§4.2.3), and
/// any scheme we do not implement.
pub fn schemeAlgorithm(scheme: proto.SignatureScheme, version: Version) ?sig.Algorithm {
    return switch (scheme) {
        .ecdsa_secp256r1_sha256 => .ecdsa_sha256,
        .ecdsa_secp384r1_sha384 => .ecdsa_sha384,
        .ecdsa_secp521r1_sha512 => .ecdsa_sha512,
        .ed25519 => .ed25519,
        .rsa_pss_rsae_sha256 => .rsa_pss_sha256,
        .rsa_pss_rsae_sha384 => .rsa_pss_sha384,
        .rsa_pss_rsae_sha512 => .rsa_pss_sha512,
        .rsa_pkcs1_sha256 => if (version == .tls12) .rsa_pkcs1_sha256 else null,
        .rsa_pkcs1_sha384 => if (version == .tls12) .rsa_pkcs1_sha384 else null,
        .rsa_pkcs1_sha512 => if (version == .tls12) .rsa_pkcs1_sha512 else null,
        else => null,
    };
}

/// Whether a key of `key_type` may sign a handshake under `scheme` in
/// `version`: the algorithm must suit the kind of key, and in TLS 1.3 an
/// ECDSA scheme names the key's curve too (§4.2.3). TLS 1.2 schemes name
/// only the hash (RFC 5246 §7.4.1.4.1); there the leaf's curve is checked
/// against supported_groups instead.
pub fn schemeSuits(scheme: proto.SignatureScheme, key_type: sig.KeyType, version: Version) bool {
    const algorithm = schemeAlgorithm(scheme, version) orelse return false;
    if (!algorithm.suits(key_type)) return false;
    if (version == .tls12) return true;
    const curve: sig.Curve = switch (scheme) {
        .ecdsa_secp256r1_sha256 => .p256,
        .ecdsa_secp384r1_sha384 => .p384,
        .ecdsa_secp521r1_sha512 => .p521,
        else => return true,
    };
    return switch (key_type) {
        .ecdsa => |key_curve| key_curve == curve,
        else => false,
    };
}

/// Whether `schemes` are all ones we implement, none twice.
pub fn schemesSupported(schemes: []const proto.SignatureScheme) bool {
    for (schemes, 0..) |scheme, i| {
        if (std.mem.indexOfScalar(proto.SignatureScheme, &config.default_signature_schemes, scheme) == null) return false;
        if (std.mem.indexOfScalar(proto.SignatureScheme, schemes[0..i], scheme) != null) return false;
    }
    return true;
}

/// The scheme to sign with in `version`: the first of `ours` that the
/// peer offered and that suits the key.
pub fn selectScheme(ours: []const proto.SignatureScheme, key_type: sig.KeyType, offered: []const proto.SignatureScheme, version: Version) ?proto.SignatureScheme {
    for (ours) |scheme| {
        if (!schemeSuits(scheme, key_type, version)) continue;
        if (std.mem.indexOfScalar(proto.SignatureScheme, offered, scheme) != null) return scheme;
    }
    return null;
}

/// Verifies a peer's chain, leaf first, against `store`, for its role.
/// `host` is the name or IP literal a server must be certified for.
pub fn verifyChain(chain: []const x509.Certificate, store: *const x509.TrustStore, purpose: x509.Purpose, host: ?[]const u8, now: i64) api.Error!void {
    var options: x509.VerifyOptions = .{ .now = now, .purpose = purpose };
    // `options.ip` points into this.
    var address: std.Io.net.IpAddress = undefined;
    if (host) |name| {
        if (std.Io.net.IpAddress.parse(name, 0)) |parsed| {
            address = parsed;
            options.ip = switch (address) {
                .ip4 => |*a| &a.bytes,
                .ip6 => |*a| &a.bytes,
            };
        } else |_| {
            options.host = name;
        }
    }
    x509.verify(store, chain, options) catch |err| return switch (err) {
        error.CertificateExpired => error.CertificateExpired,
        error.CertificateNotYetValid => error.CertificateNotYetValid,
        error.UnknownCa => error.CertificateIssuerNotFound,
        error.HostnameMismatch => error.CertificateHostMismatch,
        error.BadCertificate => error.TlsBadCertificate,
        error.CryptoFailed => error.TlsInternalError,
    };
}

const testing = std.testing;

test "scheme selection" {
    try testing.expectEqual(proto.SignatureScheme.ecdsa_secp256r1_sha256, selectScheme(&config.default_signature_schemes, .{ .ecdsa = .p256 }, &.{ .rsa_pss_rsae_sha256, .ecdsa_secp256r1_sha256 }, .tls13).?);
    try testing.expectEqual(null, selectScheme(&config.default_signature_schemes, .{ .ecdsa = .p256 }, &.{ .rsa_pss_rsae_sha256, .ecdsa_secp384r1_sha384 }, .tls13));
    try testing.expectEqual(proto.SignatureScheme.rsa_pss_rsae_sha384, selectScheme(&config.default_signature_schemes, .{ .rsa = 2048 }, &.{ .rsa_pkcs1_sha256, .rsa_pss_rsae_sha384 }, .tls13).?);
    try testing.expectEqual(null, selectScheme(&config.default_signature_schemes, .{ .rsa = 2048 }, &.{.rsa_pkcs1_sha256}, .tls13)); // pkcs1 may not sign a CertificateVerify
    try testing.expectEqual(proto.SignatureScheme.ed25519, selectScheme(&config.default_signature_schemes, .ed25519, &.{.ed25519}, .tls13).?);
    // Our order, not the peer's; and only what we list.
    try testing.expectEqual(proto.SignatureScheme.rsa_pss_rsae_sha512, selectScheme(&.{ .rsa_pss_rsae_sha512, .rsa_pss_rsae_sha256 }, .{ .rsa = 2048 }, &.{ .rsa_pss_rsae_sha256, .rsa_pss_rsae_sha512 }, .tls13).?);
    try testing.expectEqual(null, selectScheme(&.{.rsa_pss_rsae_sha384}, .{ .rsa = 2048 }, &.{.rsa_pss_rsae_sha256}, .tls13));
}

test "TLS 1.3 binds each ECDSA scheme to a curve" {
    try testing.expect(schemeSuits(.ecdsa_secp256r1_sha256, .{ .ecdsa = .p256 }, .tls13));
    try testing.expect(!schemeSuits(.ecdsa_secp256r1_sha256, .{ .ecdsa = .p384 }, .tls13));
    try testing.expect(schemeSuits(.ecdsa_secp384r1_sha384, .{ .ecdsa = .p384 }, .tls13));
    try testing.expect(!schemeSuits(.ecdsa_secp384r1_sha384, .{ .ecdsa = .p521 }, .tls13));
    try testing.expect(schemeSuits(.ecdsa_secp521r1_sha512, .{ .ecdsa = .p521 }, .tls13));
    try testing.expect(!schemeSuits(.ecdsa_secp521r1_sha512, .{ .rsa = 2048 }, .tls13));
    try testing.expect(schemeSuits(.rsa_pss_rsae_sha256, .{ .rsa = 4096 }, .tls13));
    try testing.expect(!schemeSuits(.rsa_pkcs1_sha256, .{ .rsa = 2048 }, .tls13));
    try testing.expect(!schemeSuits(.ed25519, .{ .ecdsa = .p256 }, .tls13));
}

test "TLS 1.2 schemes name the hash only, and take PKCS#1 v1.5" {
    try testing.expect(schemeSuits(.ecdsa_secp256r1_sha256, .{ .ecdsa = .p384 }, .tls12));
    try testing.expect(schemeSuits(.ecdsa_secp521r1_sha512, .{ .ecdsa = .p256 }, .tls12));
    try testing.expect(!schemeSuits(.ecdsa_secp256r1_sha256, .{ .rsa = 2048 }, .tls12));
    try testing.expect(schemeSuits(.rsa_pkcs1_sha256, .{ .rsa = 2048 }, .tls12));
    try testing.expect(schemeSuits(.rsa_pss_rsae_sha512, .{ .rsa = 2048 }, .tls12));
    try testing.expect(!schemeSuits(.rsa_pkcs1_sha384, .{ .ecdsa = .p384 }, .tls12));
    try testing.expect(schemeSuits(.ed25519, .ed25519, .tls12));
    try testing.expect(!schemeSuits(.rsa_pkcs1_sha1, .{ .rsa = 2048 }, .tls12));
    try testing.expectEqual(proto.SignatureScheme.rsa_pkcs1_sha256, selectScheme(&config.default_signature_schemes, .{ .rsa = 2048 }, &.{.rsa_pkcs1_sha256}, .tls12).?);
}

test "a host longer than 255 bytes, or starting with a dot, is a misconfiguration" {
    const long: [256]u8 = @splat('a');
    try checkClient(.{ .io = testing.io, .gpa = testing.allocator, .host = long[0..255], .insecure_skip_verify = true, .now = undefined });
    try testing.expectError(error.TlsInternalError, checkClient(.{ .io = testing.io, .gpa = testing.allocator, .host = &long, .insecure_skip_verify = true, .now = undefined }));
    try testing.expectError(error.TlsInternalError, checkClient(.{ .io = testing.io, .gpa = testing.allocator, .host = ".example.com", .insecure_skip_verify = true, .now = undefined }));
}

test "a key share for a group listed twice is a misconfiguration" {
    const opt: config.Client = .{
        .io = testing.io,
        .gpa = testing.allocator,
        .host = "localhost",
        .insecure_skip_verify = true,
        .now = undefined,
        .named_groups = &.{.secp256r1},
        .key_shares = &.{ .secp256r1, .secp256r1 },
    };
    try testing.expectError(error.TlsInternalError, checkClient(opt));
}

test "the default suites put ChaCha20-Poly1305 first without AES hardware" {
    const default: []const proto.CipherSuite = &config.default_cipher_suites;
    try testing.expectEqual(default, offeredSuites(default, true));
    const chacha = offeredSuites(default, false);
    try testing.expectEqual(proto.CipherSuite.chacha20_poly1305_sha256, chacha[0]);
    // The same suites, in an order of the same versions.
    try testing.expectEqual(default.len, chacha.len);
    for (default, chacha) |a, b| {
        try testing.expect(std.mem.indexOfScalar(proto.CipherSuite, chacha, a) != null);
        try testing.expectEqual(a.version(), b.version());
    }
    // A list of one's own is offered as given.
    const own = [_]proto.CipherSuite{ .aes_256_gcm_sha384, .chacha20_poly1305_sha256 };
    try testing.expectEqual(@as([]const proto.CipherSuite, &own), offeredSuites(&own, false));
}

test "the server's suite is the first of ours the client offers" {
    // GREASE, a TLS 1.2 suite, then the client's first TLS 1.3 one.
    const offered = [_]u8{ 0x0a, 0x0a, 0xc0, 0x2b, 0x13, 0x03, 0x13, 0x01, 0x13, 0x02 };
    try testing.expectEqual(proto.CipherSuite.aes_256_gcm_sha384, chooseSuite(&(.{.ecdhe_ecdsa_with_aes_128_gcm_sha256} ++ .{ .aes_256_gcm_sha384, .aes_128_gcm_sha256 }), &offered, true));
    // The default list, with the client listing ChaCha20 first: it lacks
    // AES instructions.
    try testing.expectEqual(proto.CipherSuite.chacha20_poly1305_sha256, chooseSuite(&proto.CipherSuite.all, &offered, true));
    try testing.expectEqual(proto.CipherSuite.aes_128_gcm_sha256, chooseSuite(&proto.CipherSuite.all, offered[6..], true));
    try testing.expectEqual(null, chooseSuite(&.{.aes_256_gcm_sha384}, offered[0..8], true));
}

test "the default suites prefer ChaCha20-Poly1305 when either side lacks AES hardware" {
    const default: []const proto.CipherSuite = &proto.CipherSuite.all;
    try testing.expectEqual(default, preferredSuites(default, true, .aes_128_gcm_sha256));
    try testing.expectEqual(default, preferredSuites(default, true, null));
    for ([_]struct { bool, ?proto.CipherSuite }{ .{ false, .aes_128_gcm_sha256 }, .{ true, .chacha20_poly1305_sha256 } }) |case| {
        const ours = preferredSuites(default, case[0], case[1]);
        try testing.expectEqual(proto.CipherSuite.chacha20_poly1305_sha256, ours[0]);
        try testing.expectEqual(default.len, ours.len);
    }
    // A list of one's own is followed as given.
    const own = [_]proto.CipherSuite{.aes_128_gcm_sha256};
    try testing.expectEqual(@as([]const proto.CipherSuite, &own), preferredSuites(&own, false, .chacha20_poly1305_sha256));
}
