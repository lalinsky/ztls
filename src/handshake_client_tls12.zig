//! The client's side of a TLS 1.2 handshake (RFC 5246), from the
//! ServerHello on: ECDHE (RFC 8422) with an AEAD suite, a server
//! certified with an RSA, ECDSA or Ed25519 key, and the extended master
//! secret (RFC 7627) when the server agrees to it. No resumption and no
//! renegotiation.

const std = @import("std");
const proto = @import("protocol.zig");
const codec = @import("codec.zig");
const cipher = @import("cipher.zig");
const config = @import("config.zig");
const crypto = @import("crypto.zig");
const sig = crypto.sig;
const handshake = @import("handshake.zig");
const Handshake = handshake.Handshake;
const KeyShares = handshake.KeyShares;
const Error = handshake.Error;

/// What a TLS 1.2 ServerHello settles.
pub const ServerHello = struct {
    suite: proto.CipherSuite,
    random: [32]u8,
    extended_master_secret: bool = false,
    /// Our own slice.
    alpn: ?[]const u8 = null,
};

/// The two randoms, which the PRF and the ServerKeyExchange signature take.
const Randoms = struct {
    client: *const [32]u8,
    server: *const [32]u8,
};

const master_secret_len = 48;
const verify_data_len = 12;

/// Runs the handshake after the ServerHello, which `h` has hashed, with
/// the suite set.
pub fn run(h: *Handshake, opt: config.Client, client_random: *const [32]u8, hello: ServerHello) Error!void {
    const suite = h.suite;
    const randoms: Randoms = .{ .client = client_random, .server = &hello.random };
    const hash_algorithm = cipher.suiteHash(suite).?;
    // Every record from here on says TLS 1.2.
    h.conn.read.check_record_version = true;

    var msg = try h.nextMessage();
    try h.expect(msg, .certificate);
    // A server's chain is never empty (RFC 5246 §7.4.2).
    var peer = (try h.parseCertificateTls12(msg.body)) orelse return error.TlsDecodeError;
    defer peer.deinit();
    try checkLeaf(&peer, suite, opt.named_groups);
    h.conn.peer_key_type = peer.public_key.key_type;
    if (!opt.insecure_skip_verify) {
        try h.verifyChain(&peer, opt.root_ca.?, .server, opt.host, opt.now.toSeconds());
    }
    try h.hashMessage(msg);

    msg = try h.nextMessage();
    try h.expect(msg, .server_key_exchange);
    const exchange = try parseServerKeyExchange(msg.body, opt, &peer.public_key, randoms);
    h.conn.peer_signature_scheme = exchange.scheme;
    try h.hashMessage(msg);

    msg = try h.nextMessage();
    var request: ?CertificateRequest = null;
    if (msg.handshake_type == .certificate_request) {
        request = try parseCertificateRequest(msg.body, opt.auth, opt.signing_schemes);
        try h.hashMessage(msg);
        msg = try h.nextMessage();
    }
    // Only a CertificateVerify needs the messages themselves.
    if (request == null or request.?.scheme == null) h.dropRawTranscript();

    try h.expect(msg, .server_hello_done);
    if (msg.body.len != 0) return error.TlsDecodeError;
    try h.expectFlightEnd();
    try h.hashMessage(msg);

    // Our share, and the premaster secret, in one step.
    var share_buf: [KeyShares.max_share_len]u8 = undefined;
    var premaster_buf: [KeyShares.max_secret_len]u8 = undefined;
    defer std.crypto.secureZero(u8, &premaster_buf);
    const response = try KeyShares.respond(exchange.group, exchange.point(), &share_buf, &premaster_buf);
    h.conn.group = exchange.group;

    // Our flight: our certificate if asked, or an empty one when we have
    // none that fits, which the server may accept or refuse (§7.4.6).
    if (request) |req| try writeCertificate(h, if (req.scheme != null) opt.auth.? else null);
    try writeClientKeyExchange(h, response.share);

    var master: [master_secret_len]u8 = undefined;
    defer std.crypto.secureZero(u8, &master);
    if (hello.extended_master_secret) {
        // RFC 7627 §4: the session hash runs through ClientKeyExchange.
        var hash_buf: [crypto.hash.max_digest_length]u8 = undefined;
        const session_hash = h.transcriptHash(&hash_buf);
        crypto.prf.tls12(hash_algorithm, response.secret, "extended master secret", session_hash, "", &master);
    } else {
        crypto.prf.tls12(hash_algorithm, response.secret, "master secret", randoms.client, randoms.server, &master);
    }
    // After ClientKeyExchange, and outside the session hash.
    if (request) |req| if (req.scheme) |scheme| {
        try h.writeCertificateVerifyTls12(opt.auth.?, scheme);
        h.dropRawTranscript();
    };

    var keys = try KeyBlock.derive(suite, &master, randoms);
    defer keys.wipe();

    h.conn.writeChangeCipherSpec() catch return error.WriteFailed;
    var write_keys = keys.clientKeys() catch return error.TlsInternalError;
    cipher.Keys.replace(&h.conn.write.keys, &write_keys);
    try writeFinished(h, hash_algorithm, &master);
    try h.flush();

    // The server's ChangeCipherSpec switches its direction to the new keys
    // and its Finished, the first message under them, closes the
    // handshake.
    try h.readChangeCipherSpec();
    var read_keys = keys.serverKeys() catch return error.TlsInternalError;
    cipher.Keys.replace(&h.conn.read.keys, &read_keys);

    msg = try h.nextMessage();
    try h.expect(msg, .finished);
    try h.expectFlightEnd();
    try verifyFinished(h, hash_algorithm, &master, msg.body);
    try h.hashMessage(msg);

    h.conn.read.ccs = .refuse;
    h.conn.alpn_protocol = hello.alpn;
    h.conn.strict_close_notify = opt.strict_close_notify;
}

/// What a suite's server signs its key exchange with.
const Authentication = enum { ecdsa, rsa };

fn suiteAuthentication(suite: proto.CipherSuite) Authentication {
    return switch (suite) {
        .ecdhe_ecdsa_with_aes_128_gcm_sha256,
        .ecdhe_ecdsa_with_aes_256_gcm_sha384,
        .ecdhe_ecdsa_with_chacha20_poly1305_sha256,
        => .ecdsa,
        .ecdhe_rsa_with_aes_128_gcm_sha256,
        .ecdhe_rsa_with_aes_256_gcm_sha384,
        .ecdhe_rsa_with_chacha20_poly1305_sha256,
        => .rsa,
        else => unreachable,
    };
}

/// The leaf's key must be of the kind the suite names (ECDHE_ECDSA also
/// covers Ed25519, RFC 8422 §2.3), as AWS-LC checks, and must be allowed
/// to sign: BoringSSL (and so Chrome) holds RSA leaves to that too, so a
/// keyEncipherment-only one is refused. An ECDSA key must be on a curve
/// we offered in supported_groups (RFC 8422 §5.1).
fn checkLeaf(peer: *const handshake.PeerCertificate, suite: proto.CipherSuite, named_groups: []const proto.NamedGroup) Error!void {
    const key_type = peer.public_key.key_type;
    switch (suiteAuthentication(suite)) {
        .rsa => if (key_type != .rsa) return error.TlsIllegalParameter,
        .ecdsa => {
            switch (key_type) {
                .ecdsa => |curve| {
                    const group: proto.NamedGroup = switch (curve) {
                        .p256 => .secp256r1,
                        .p384 => .secp384r1,
                        .p521 => .secp521r1,
                    };
                    if (std.mem.indexOfScalar(proto.NamedGroup, named_groups, group) == null) return error.TlsIllegalParameter;
                },
                .ed25519 => {},
                .rsa => return error.TlsIllegalParameter,
            }
        },
    }
    if (!peer.chain[0].allowsDigitalSignature()) return error.TlsBadCertificate;
}

/// The server's ECDHE parameters, copied out of the message, which does
/// not outlive the next one read.
const KeyExchange = struct {
    group: proto.NamedGroup,
    point_buf: [255]u8,
    point_len: u8,
    scheme: proto.SignatureScheme,

    fn point(e: *const KeyExchange) []const u8 {
        return e.point_buf[0..e.point_len];
    }
};

/// The server's ECDHE parameters (RFC 8422 §5.4) and its signature over
/// them and both randoms, made with the leaf's key.
fn parseServerKeyExchange(body: []const u8, opt: config.Client, public_key: *const sig.PublicKey, randoms: Randoms) Error!KeyExchange {
    var d = codec.Decoder.init(body);
    // ECCurveType: named_curve only; explicit curves are long gone.
    if (try d.decode(u8) != 3) return error.TlsIllegalParameter;
    const group = try d.decode(proto.NamedGroup);
    const point = try d.vectorBytes(u8);
    if (point.len == 0) return error.TlsDecodeError;
    const params = body[0 .. body.len - d.remaining()];
    const scheme = try d.decode(proto.SignatureScheme);
    const signature = try d.vectorBytes(u16);
    try d.expectEof();

    // A group we offered, and one TLS 1.2 can use: the hybrid is TLS 1.3's.
    if (std.mem.indexOfScalar(proto.NamedGroup, opt.named_groups, group) == null) return error.TlsIllegalParameter;
    switch (group) {
        .x25519, .secp256r1, .secp384r1 => {},
        else => return error.TlsIllegalParameter,
    }
    if (std.mem.indexOfScalar(proto.SignatureScheme, opt.verify_schemes, scheme) == null) return error.TlsIllegalParameter;
    if (!handshake.schemeSuits(scheme, public_key.key_type, .tls12)) return error.TlsIllegalParameter;
    const algorithm = handshake.schemeAlgorithm(scheme, .tls12).?;

    var content_buf: [32 + 32 + 4 + 255]u8 = undefined;
    var w = codec.Writer.init(&content_buf);
    w.slice(randoms.client) catch unreachable;
    w.slice(randoms.server) catch unreachable;
    w.slice(params) catch unreachable;
    public_key.verify(algorithm, w.written(), signature) catch |err| return switch (err) {
        error.SignatureInvalid => error.TlsDecryptError,
        error.AlgorithmMismatch => error.TlsIllegalParameter,
        error.CryptoFailed => error.TlsInternalError,
    };
    var exchange: KeyExchange = .{ .group = group, .point_buf = undefined, .point_len = @intCast(point.len), .scheme = scheme };
    @memcpy(exchange.point_buf[0..point.len], point);
    return exchange;
}

const CertificateRequest = struct {
    /// The scheme our certificate answers with, or null to send none.
    scheme: ?proto.SignatureScheme,
};

/// ClientCertificateType values (RFC 5246 §7.4.4, RFC 8422 §5.5).
const rsa_sign = 1;
const ecdsa_sign = 64;

/// A TLS 1.2 CertificateRequest (RFC 5246 §7.4.4): the kinds of key and
/// the schemes the server takes, and the authorities it trusts, which
/// only narrow what it would like; we offer what we have.
fn parseCertificateRequest(body: []const u8, auth: ?*const config.CertKeyPair, signing: []const proto.SignatureScheme) Error!CertificateRequest {
    var d = codec.Decoder.init(body);
    const types = try d.vectorBytes(u8);
    if (types.len == 0) return error.TlsDecodeError;
    var schemes = try d.vector(u16);
    if (schemes.eof()) return error.TlsDecodeError;
    var authorities = try d.vector(u16);
    try d.expectEof();
    while (!authorities.eof()) {
        if ((try authorities.vectorBytes(u16)).len == 0) return error.TlsDecodeError;
    }
    var offered: [64]proto.SignatureScheme = undefined;
    var n: usize = 0;
    while (!schemes.eof()) {
        const scheme = try schemes.decode(proto.SignatureScheme);
        if (n < offered.len) {
            offered[n] = scheme;
            n += 1;
        }
    }

    const pair = auth orelse return .{ .scheme = null };
    const key_type = pair.key.key_type;
    // Ed25519 goes under ecdsa_sign (RFC 8422 §5.5).
    const wanted_type: u8 = switch (key_type) {
        .rsa => rsa_sign,
        .ecdsa, .ed25519 => ecdsa_sign,
    };
    if (std.mem.indexOfScalar(u8, types, wanted_type) == null) return .{ .scheme = null };
    // A scheme naming our key's curve first, as TLS 1.3 would have it,
    // then any the key can sign under in TLS 1.2.
    const scheme = handshake.selectScheme(signing, key_type, offered[0..n], .tls13) orelse
        handshake.selectScheme(signing, key_type, offered[0..n], .tls12);
    return .{ .scheme = scheme };
}

/// A TLS 1.2 Certificate (RFC 5246 §7.4.2): `pair`'s chain, or none.
fn writeCertificate(h: *Handshake, pair: ?*const config.CertKeyPair) Error!void {
    const chain: []const []const u8 = if (pair) |p| p.chain else &.{};
    var list_len: usize = 0;
    for (chain) |der| list_len += 3 + der.len;
    if (list_len > std.math.maxInt(u24) - 3) return error.TlsInternalError;

    var w = try h.messageWriter();
    try w.write(&.{@intFromEnum(proto.HandshakeType.certificate)});
    try w.int(u24, 3 + list_len);
    try w.int(u24, list_len);
    for (chain) |der| {
        try w.int(u24, der.len);
        try w.write(der);
    }
    try w.finish();
}

fn writeClientKeyExchange(h: *Handshake, share: []const u8) Error!void {
    var buf: [4 + 1 + KeyShares.max_share_len]u8 = undefined;
    var w = codec.Writer.init(&buf);
    w.enumValue(proto.HandshakeType.client_key_exchange) catch unreachable;
    const len = w.beginLength(u24) catch unreachable;
    w.vector(u8, share) catch unreachable;
    len.end(&w) catch unreachable;
    try h.writeMessage(w.written());
}

/// The key block (RFC 5246 §6.3), cut into the two directions' write keys
/// and IVs; AEAD suites have no MAC keys.
const KeyBlock = struct {
    algorithm: crypto.aead.Algorithm,
    bytes: [2 * crypto.aead.max_key_length + 2 * crypto.aead.nonce_length]u8,

    fn derive(suite: proto.CipherSuite, master: *const [master_secret_len]u8, randoms: Randoms) Error!KeyBlock {
        var block: KeyBlock = .{ .algorithm = cipher.suiteAead(suite).?, .bytes = undefined };
        crypto.prf.tls12(cipher.suiteHash(suite).?, master, "key expansion", randoms.server, randoms.client, block.bytes[0..block.len()]);
        return block;
    }

    fn keyLen(b: *const KeyBlock) usize {
        return b.algorithm.keyLength();
    }

    fn ivLen(b: *const KeyBlock) usize {
        return cipher.tls12FixedIvLen(b.algorithm);
    }

    fn len(b: *const KeyBlock) usize {
        return 2 * b.keyLen() + 2 * b.ivLen();
    }

    // client_write_key, server_write_key, client_write_IV, server_write_IV
    fn clientKeys(b: *const KeyBlock) crypto.err.Error!cipher.Keys {
        return cipher.Keys.initTls12(b.algorithm, b.bytes[0..b.keyLen()], b.bytes[2 * b.keyLen() ..][0..b.ivLen()]);
    }

    fn serverKeys(b: *const KeyBlock) crypto.err.Error!cipher.Keys {
        return cipher.Keys.initTls12(b.algorithm, b.bytes[b.keyLen()..][0..b.keyLen()], b.bytes[2 * b.keyLen() + b.ivLen() ..][0..b.ivLen()]);
    }

    fn wipe(b: *KeyBlock) void {
        std.crypto.secureZero(u8, &b.bytes);
    }
};

/// verify_data (RFC 5246 §7.4.9): the PRF over the transcript so far.
fn verifyData(h: *const Handshake, hash_algorithm: crypto.hash.Algorithm, master: *const [master_secret_len]u8, label: []const u8) [verify_data_len]u8 {
    var hash_buf: [crypto.hash.max_digest_length]u8 = undefined;
    var out: [verify_data_len]u8 = undefined;
    crypto.prf.tls12(hash_algorithm, master, label, h.transcriptHash(&hash_buf), "", &out);
    return out;
}

fn writeFinished(h: *Handshake, hash_algorithm: crypto.hash.Algorithm, master: *const [master_secret_len]u8) Error!void {
    var message: [4 + verify_data_len]u8 = .{ @intFromEnum(proto.HandshakeType.finished), 0, 0, verify_data_len } ++ @as([verify_data_len]u8, undefined);
    message[4..].* = verifyData(h, hash_algorithm, master, "client finished");
    try h.writeMessage(&message);
}

fn verifyFinished(h: *const Handshake, hash_algorithm: crypto.hash.Algorithm, master: *const [master_secret_len]u8, body: []const u8) Error!void {
    // A Finished of the wrong length fails as a wrong one does, as AWS-LC
    // has it.
    if (body.len != verify_data_len) return error.TlsDecryptError;
    const expected = verifyData(h, hash_algorithm, master, "server finished");
    if (!std.crypto.timing_safe.eql([verify_data_len]u8, expected, body[0..verify_data_len].*)) return error.TlsDecryptError;
}

const testing = std.testing;

/// A ServerKeyExchange for `group` with a dummy point, signed by `pair`.
fn testServerKeyExchange(buf: []u8, pair: *const config.CertKeyPair, randoms: Randoms, curve_type: u8, group: proto.NamedGroup, scheme: proto.SignatureScheme) ![]u8 {
    var w = codec.Writer.init(buf);
    try w.byte(curve_type);
    try w.enumValue(group);
    try w.vector(u8, &@as([32]u8, @splat(9)));
    const params_len = w.written().len;
    var content: [512]u8 = undefined;
    @memcpy(content[0..32], randoms.client);
    @memcpy(content[32..64], randoms.server);
    @memcpy(content[64..][0..params_len], w.written());
    var sig_buf: [512]u8 = undefined;
    // A scheme the key cannot sign under gets an ECDSA signature anyway.
    const algorithm: crypto.sig.Algorithm = if (handshake.schemeSuits(scheme, pair.key.key_type, .tls12)) handshake.schemeAlgorithm(scheme, .tls12).? else .ecdsa_sha256;
    const signature = try pair.key.sign(algorithm, content[0 .. 64 + params_len], &sig_buf);
    try w.enumValue(scheme);
    try w.vector(u16, signature);
    return w.written();
}

test "a ServerKeyExchange is signed over both randoms, with a group and scheme we offered" {
    if (!proto.tls12_enabled) return error.SkipZigTest;
    var pair = try config.CertKeyPair.fromSlice(testing.allocator, @embedFile("testdata/pki/server-ec.pem"), @embedFile("testdata/pki/server-ec.key"));
    defer pair.deinit(testing.allocator);
    var public = try pair.leaf.publicKey();
    defer public.deinit();
    const client_random: [32]u8 = @splat(1);
    const server_random: [32]u8 = @splat(2);
    const hello: Randoms = .{ .client = &client_random, .server = &server_random };
    const opt: config.Client = .{ .allocator = testing.allocator, .host = "localhost", .insecure_skip_verify = true, .now = undefined };
    var buf: [512]u8 = undefined;

    const body = try testServerKeyExchange(&buf, &pair, hello, 3, .x25519, .ecdsa_secp256r1_sha256);
    const exchange = try parseServerKeyExchange(body, opt, &public, hello);
    try testing.expectEqual(proto.NamedGroup.x25519, exchange.group);
    try testing.expectEqual(proto.SignatureScheme.ecdsa_secp256r1_sha256, exchange.scheme);
    try testing.expectEqualSlices(u8, &@as([32]u8, @splat(9)), exchange.point());
    // A flipped bit in the signature, or other randoms.
    body[body.len - 1] ^= 1;
    try testing.expectError(error.TlsDecryptError, parseServerKeyExchange(body, opt, &public, hello));
    // In TLS 1.2 the scheme's curve is not the key's: P-256 under SHA-384.
    _ = try parseServerKeyExchange(try testServerKeyExchange(&buf, &pair, hello, 3, .x25519, .ecdsa_secp384r1_sha384), opt, &public, hello);
    var other_random = server_random;
    other_random[0] ^= 1;
    const other: Randoms = .{ .client = &client_random, .server = &other_random };
    try testing.expectError(error.TlsDecryptError, parseServerKeyExchange(try testServerKeyExchange(&buf, &pair, hello, 3, .x25519, .ecdsa_secp256r1_sha256), opt, &public, other));

    // A scheme for another kind of key, explicit curves, the TLS 1.3
    // hybrid, and a group we did not offer.
    try testing.expectError(error.TlsIllegalParameter, parseServerKeyExchange(try testServerKeyExchange(&buf, &pair, hello, 3, .x25519, .rsa_pkcs1_sha256), opt, &public, hello));
    try testing.expectError(error.TlsIllegalParameter, parseServerKeyExchange(try testServerKeyExchange(&buf, &pair, hello, 1, .x25519, .ecdsa_secp256r1_sha256), opt, &public, hello));
    try testing.expectError(error.TlsIllegalParameter, parseServerKeyExchange(try testServerKeyExchange(&buf, &pair, hello, 3, .x25519_ml_kem768, .ecdsa_secp256r1_sha256), opt, &public, hello));
    try testing.expectError(error.TlsIllegalParameter, parseServerKeyExchange(try testServerKeyExchange(&buf, &pair, hello, 3, .secp521r1, .ecdsa_secp256r1_sha256), opt, &public, hello));
}

test "a CertificateRequest picks our key's scheme, curve first, if its types allow the key" {
    if (!proto.tls12_enabled) return error.SkipZigTest;
    var ec = try config.CertKeyPair.fromSlice(testing.allocator, @embedFile("testdata/pki/client.pem"), @embedFile("testdata/pki/client.key"));
    defer ec.deinit(testing.allocator);
    var rsa = try config.CertKeyPair.fromSlice(testing.allocator, @embedFile("testdata/pki/server-rsa.pem"), @embedFile("testdata/pki/server-rsa.key"));
    defer rsa.deinit(testing.allocator);
    const Scheme = proto.SignatureScheme;

    const request = struct {
        fn build(buf: []u8, types: []const u8, schemes: []const Scheme) ![]const u8 {
            var w = codec.Writer.init(buf);
            try w.vector(u8, types);
            try w.enumList(schemes);
            try w.vector(u16, &.{});
            return w.written();
        }
    }.build;
    var buf: [128]u8 = undefined;

    // The P-256 key: its own curve's scheme when offered, else another.
    var r = try parseCertificateRequest(try request(&buf, &.{ rsa_sign, ecdsa_sign }, &.{ .rsa_pss_rsae_sha256, .ecdsa_secp384r1_sha384, .ecdsa_secp256r1_sha256 }), &ec, &config.default_signature_schemes);
    try testing.expectEqual(Scheme.ecdsa_secp256r1_sha256, r.scheme.?);
    r = try parseCertificateRequest(try request(&buf, &.{ecdsa_sign}, &.{.ecdsa_secp384r1_sha384}), &ec, &config.default_signature_schemes);
    try testing.expectEqual(Scheme.ecdsa_secp384r1_sha384, r.scheme.?);
    // Not when the types leave EC keys out, nor with no scheme for it.
    r = try parseCertificateRequest(try request(&buf, &.{rsa_sign}, &.{.ecdsa_secp256r1_sha256}), &ec, &config.default_signature_schemes);
    try testing.expectEqual(null, r.scheme);
    r = try parseCertificateRequest(try request(&buf, &.{ecdsa_sign}, &.{.rsa_pkcs1_sha256}), &ec, &config.default_signature_schemes);
    try testing.expectEqual(null, r.scheme);
    // RSA: PSS first, PKCS#1 v1.5 when that is all there is.
    r = try parseCertificateRequest(try request(&buf, &.{rsa_sign}, &.{ .rsa_pkcs1_sha256, .rsa_pss_rsae_sha256 }), &rsa, &config.default_signature_schemes);
    try testing.expectEqual(Scheme.rsa_pss_rsae_sha256, r.scheme.?);
    r = try parseCertificateRequest(try request(&buf, &.{rsa_sign}, &.{.rsa_pkcs1_sha384}), &rsa, &config.default_signature_schemes);
    try testing.expectEqual(Scheme.rsa_pkcs1_sha384, r.scheme.?);
    // No certificate configured; and malformed lists.
    r = try parseCertificateRequest(try request(&buf, &.{ecdsa_sign}, &.{.ecdsa_secp256r1_sha256}), null, &config.default_signature_schemes);
    try testing.expectEqual(null, r.scheme);
    try testing.expectError(error.TlsDecodeError, parseCertificateRequest(try request(&buf, &.{}, &.{.ecdsa_secp256r1_sha256}), &ec, &config.default_signature_schemes));
    try testing.expectError(error.TlsDecodeError, parseCertificateRequest(try request(&buf, &.{ecdsa_sign}, &.{}), &ec, &config.default_signature_schemes));
}
