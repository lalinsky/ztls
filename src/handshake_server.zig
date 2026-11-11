//! The server's side of the handshake (RFC 9846 §2): the ClientHello, a
//! HelloRetryRequest when the client sent no share we can use, our flight,
//! then the client's Finished (and certificate, if we asked).

const std = @import("std");
const proto = @import("protocol.zig");
const codec = @import("codec.zig");
const config = @import("config.zig");
const crypto = @import("crypto.zig");
const handshake = @import("handshake.zig");
const Handshake = handshake.Handshake;
const KeyShares = handshake.KeyShares;
const Error = handshake.Error;
const Connection = @import("connection.zig").Connection;

pub fn run(conn: *Connection, options: config.Server) Error!void {
    try checkOptions(options);
    // No Certificate is taken from a client that is not asked for one, so
    // nothing needs more than the small limit.
    const max_message_len = if (options.client_auth == null) @min(options.max_handshake_message_len, handshake.max_small_message_len) else options.max_handshake_message_len;
    var h = Handshake.init(conn, options.allocator, max_message_len);
    defer h.deinit();
    handshakeInner(&h, options) catch |err| {
        h.sendAlert(err);
        return err;
    };
}

fn checkOptions(opt: config.Server) error{TlsInternalError}!void {
    if (opt.verify_schemes.len == 0 or opt.signing_schemes.len == 0) return error.TlsInternalError;
    if (!handshake.schemesSupported(opt.verify_schemes) or !handshake.schemesSupported(opt.signing_schemes)) return error.TlsInternalError;
}

/// What a ClientHello offers. Slices point into the message.
const ClientHello = struct {
    session_id: []const u8,
    /// The cipher_suites vector, raw.
    suites: []const u8,
    /// Only those for groups we support, and the number of all of them.
    key_shares: [max_groups]KeyShare = undefined,
    key_shares_len: usize = 0,
    key_shares_offered: usize = 0,
    /// Only those we support, and only once each; so for the schemes.
    groups: [max_groups]proto.NamedGroup = undefined,
    groups_len: usize = 0,
    schemes: [max_schemes]proto.SignatureScheme = undefined,
    schemes_len: ?usize = null,
    server_name: ?[]const u8 = null,
    /// The ProtocolNameList, raw, if ALPN was offered.
    alpn: ?[]const u8 = null,
    has_cookie: bool = false,

    const max_groups = blk: {
        var n = 0;
        for (std.enums.values(proto.NamedGroup)) |group| {
            if (handshake.groupSupported(group)) n += 1;
        }
        break :blk n;
    };
    const max_schemes = config.default_signature_schemes.len;

    const KeyShare = struct {
        group: proto.NamedGroup,
        share: []const u8,
    };

    /// The client's first TLS 1.3 suite: its favourite of those we could
    /// pick, telling, if it is ChaCha20-Poly1305, that it lacks AES
    /// instructions.
    fn firstTls13Suite(ch: *const ClientHello) ?proto.CipherSuite {
        var d = codec.Decoder.init(ch.suites);
        while (!d.eof()) {
            const suite = d.decode(proto.CipherSuite) catch unreachable;
            if (suite.version() == .tls_1_3) return suite;
        }
        return null;
    }

    fn offersSuite(ch: *const ClientHello, suite: proto.CipherSuite) bool {
        var d = codec.Decoder.init(ch.suites);
        while (!d.eof()) {
            if ((d.decode(proto.CipherSuite) catch unreachable) == suite) return true;
        }
        return false;
    }

    fn supportsGroup(ch: *const ClientHello, group: proto.NamedGroup) bool {
        return std.mem.indexOfScalar(proto.NamedGroup, ch.groups[0..ch.groups_len], group) != null;
    }

    fn shareFor(ch: *const ClientHello, group: proto.NamedGroup) ?[]const u8 {
        for (ch.key_shares[0..ch.key_shares_len]) |ks| {
            if (ks.group == group) return ks.share;
        }
        return null;
    }
};

/// What we decided from a ClientHello.
const Choices = struct {
    suite: proto.CipherSuite,
    group: proto.NamedGroup,
    scheme: proto.SignatureScheme,
    alpn: ?[]const u8,
};

fn handshakeInner(h: *Handshake, opt: config.Server) Error!void {
    @setRuntimeSafety(true);
    if (opt.cipher_suites.len == 0 or opt.named_groups.len == 0) return error.TlsInternalError;

    var msg = try h.nextMessage();
    try h.expect(msg, .client_hello);
    h.ccs_allowed = true;
    try h.expectFlightEnd();
    var hello = try parseClientHello(msg.body);
    const auth = try selectCertificate(&hello, opt);
    const choices = try choose(&hello, opt, auth);
    h.setSuite(choices.suite);
    h.conn.group = choices.group;
    try h.conn.setServerName(hello.server_name);
    try h.hashMessage(msg);

    var session_id_buf: [32]u8 = undefined;
    @memcpy(session_id_buf[0..hello.session_id.len], hello.session_id);
    const session_id = session_id_buf[0..hello.session_id.len];
    // Kept across a retry to check the second hello against.
    var server_name_buf: [255]u8 = undefined;
    const server_name_len = if (hello.server_name) |name| name.len else 0;
    if (hello.server_name) |name| @memcpy(server_name_buf[0..name.len], name);

    var retried = false;
    if (hello.shareFor(choices.group) == null) {
        // No usable share: ask for one (§4.2.4).
        retried = true;
        h.conn.retried = true;
        h.transcript.replaceWithMessageHash();
        try writeServerHello(h, choices.suite, choices.group, null, session_id);
        // The middlebox-compatibility change_cipher_spec goes out whatever
        // the client's session id: §E.4 allows it at any time and peers
        // must drop it, while some expect it unconditionally.
        h.conn.writeChangeCipherSpec() catch return error.WriteFailed;
        try h.flush();

        msg = try h.nextMessage();
        try h.expect(msg, .client_hello);
        try h.expectFlightEnd();
        hello = try parseClientHello(msg.body);
        // The second hello may differ only in its key share (§4.1.2).
        // As in BoringSSL, what the first one settled stands, ALPN
        // included, and only the share is taken from this one; beyond the
        // session id and server name the rest is not compared.
        if (!std.mem.eql(u8, hello.session_id, session_id) or hello.has_cookie) return error.TlsIllegalParameter;
        if (!std.mem.eql(u8, hello.server_name orelse "", server_name_buf[0..server_name_len])) return error.TlsIllegalParameter;
        if (hello.key_shares_offered != 1 or hello.shareFor(choices.group) == null) return error.TlsIllegalParameter;
        try h.hashMessage(msg);
    }

    var share_buf: [KeyShares.max_share_len]u8 = undefined;
    var secret_buf: [KeyShares.max_secret_len]u8 = undefined;
    defer std.crypto.secureZero(u8, &secret_buf);
    const response = try KeyShares.respond(choices.group, hello.shareFor(choices.group).?, &share_buf, &secret_buf);

    try writeServerHello(h, choices.suite, choices.group, response.share, session_id);
    var hs = h.deriveHandshakeSecrets(response.secret);
    defer hs.wipe();
    try h.installWriteKeys(hs.server);
    try h.installReadKeys(hs.client);
    if (!retried) h.conn.writeChangeCipherSpec() catch return error.WriteFailed;

    try writeEncryptedExtensions(h, choices.alpn);
    if (opt.client_auth != null) try writeCertificateRequest(h, opt.verify_schemes);
    try h.writeCertificate("", auth);
    try h.writeCertificateVerify(auth, choices.scheme, .server);
    try h.writeFinished(&hs.server);
    try h.flush();

    var ap = h.deriveApplicationSecrets();
    defer ap.wipe();
    // Application data may go out before the client's Finished arrives.
    try h.installWriteKeys(ap.server);

    msg = try h.nextMessage();
    if (opt.client_auth) |client_auth| {
        try h.expect(msg, .certificate);
        var maybe_peer = try h.parseCertificate(msg.body, "");
        if (maybe_peer) |*peer| {
            defer peer.deinit();
            h.conn.peer_key_type = peer.public_key.key_type;
            try h.verifyChain(peer, client_auth.root_ca, .client, null, opt.now.toSeconds());
            try h.hashMessage(msg);
            msg = try h.nextMessage();
            try h.expect(msg, .certificate_verify);
            try h.verifyCertificateVerify(msg.body, &peer.public_key, .client, opt.verify_schemes);
            try h.hashMessage(msg);
        } else {
            if (client_auth.auth_type == .require) return error.TlsCertificateRequired;
            try h.hashMessage(msg);
        }
        msg = try h.nextMessage();
    }
    try h.expect(msg, .finished);
    try h.verifyFinished(msg.body, &hs.client);
    try h.hashMessage(msg);

    try h.installReadKeys(ap.client);
    h.conn.read.ccs = .refuse;
    h.conn.alpn_protocol = choices.alpn;
    h.conn.strict_close_notify = opt.strict_close_notify;
}

/// The certificate to present: the application's choice, else the first
/// of `certificates` for the client's server name that it can verify,
/// else `auth`.
fn selectCertificate(hello: *const ClientHello, opt: config.Server) Error!*const config.CertKeyPair {
    const schemes = hello.schemes[0..hello.schemes_len.?];
    if (opt.select_certificate) |select| {
        const info: config.SelectCertificate.Hello = .{
            .server_name = hello.server_name,
            .accepts = acceptsKey,
            .schemes = schemes,
            .signing_schemes = opt.signing_schemes,
        };
        if (select.callback(select.context, info)) |pair| return pair;
    }
    for (opt.certificates) |pair| {
        if (handshake.selectScheme(opt.signing_schemes, pair.key.key_type, schemes, .tls13) == null) continue;
        if (hello.server_name) |name| {
            if (!pair.leaf.matchesHost(name)) continue;
        }
        return pair;
    }
    return opt.auth orelse error.TlsUnrecognizedName;
}

fn acceptsKey(hello: *const config.SelectCertificate.Hello, key_type: crypto.sig.KeyType) bool {
    return handshake.selectScheme(hello.signing_schemes, key_type, hello.schemes, .tls13) != null;
}

/// Picks the suite, group, signature scheme and ALPN protocol, or says
/// why no handshake is possible.
fn choose(hello: *const ClientHello, opt: config.Server, auth: *const config.CertKeyPair) Error!Choices {
    // The server speaks TLS 1.3 only: TLS 1.2 suites in the list are passed over.
    const ours = preferredSuites(opt.cipher_suites, crypto.aead.hasAesHardware(), hello.firstTls13Suite());
    const suite = for (ours) |suite| {
        if (suite.version() == .tls_1_3 and hello.offersSuite(suite)) break suite;
    } else return error.TlsHandshakeFailure;

    // Of the groups the client sent shares for, our favourite; failing
    // that, our favourite among the ones it supports, via a retry.
    const group = for (opt.named_groups) |group| {
        if (handshake.groupSupported(group) and hello.shareFor(group) != null) break group;
    } else for (opt.named_groups) |group| {
        if (handshake.groupSupported(group) and hello.supportsGroup(group)) break group;
    } else return error.TlsHandshakeFailure;

    const schemes = hello.schemes[0..hello.schemes_len.?];
    const scheme = handshake.selectScheme(opt.signing_schemes, auth.key.key_type, schemes, .tls13) orelse return error.TlsHandshakeFailure;

    return .{ .suite = suite, .group = group, .scheme = scheme, .alpn = try selectAlpn(opt.alpn_protocols, hello.alpn) };
}

/// Our suites in preference order: the default list prefers
/// ChaCha20-Poly1305 when either side lacks AES instructions, ours or the
/// client's, which it tells by listing ChaCha20 first, as Go and BoringSSL
/// servers have it.
fn preferredSuites(suites: []const proto.CipherSuite, aes_hardware: bool, client_first: ?proto.CipherSuite) []const proto.CipherSuite {
    if (!std.mem.eql(proto.CipherSuite, suites, &proto.CipherSuite.all)) return suites;
    if (aes_hardware and client_first != .chacha20_poly1305_sha256) return suites;
    return &config.default_server_cipher_suites_chacha_first;
}

/// Our most preferred protocol the client offered. Null when either side
/// has none; an offer we share nothing with is refused (RFC 7301 §3.2).
fn selectAlpn(ours: []const []const u8, offered: ?[]const u8) Error!?[]const u8 {
    const list = offered orelse return null;
    if (ours.len == 0) return null;
    for (ours) |name| {
        var d = codec.Decoder.init(list);
        while (!d.eof()) {
            const candidate = try d.vectorBytes(u8);
            if (candidate.len == 0) return error.TlsIllegalParameter;
            if (std.mem.eql(u8, candidate, name)) return name;
        }
    }
    return error.TlsNoApplicationProtocol;
}

fn parseClientHello(body: []const u8) Error!ClientHello {
    @setRuntimeSafety(true);
    var d = codec.Decoder.init(body);
    // SSL 3.0 and older are refused (Appendix D.5). Otherwise
    // legacy_version plays no part once supported_versions is there
    // (§4.3.1), and that extension is required below.
    if (@intFromEnum(try d.decode(proto.Version)) <= 0x0300) return error.TlsProtocolVersion;
    _ = try d.array(32); // random
    const session_id = try d.vectorBytes(u8);
    if (session_id.len > 32) return error.TlsDecodeError;
    const suites = try d.vectorBytes(u16);
    if (suites.len == 0 or suites.len % 2 != 0) return error.TlsDecodeError;
    // TLS 1.3 clients offer the null compression method only (§4.2.2).
    if (!std.mem.eql(u8, try d.vectorBytes(u8), &.{0})) return error.TlsIllegalParameter;
    var extensions = try d.vector(u16);
    try d.expectEof();

    var hello: ClientHello = .{ .session_id = session_id, .suites = suites };
    var supports_1_3 = false;
    var has_key_share = false;
    var has_groups = false;
    // A repeated extension type is a malformed block (§4.3). Clients send
    // a dozen or two, GREASE included.
    var seen: [64]u16 = undefined;
    var seen_len: usize = 0;
    while (!extensions.eof()) {
        const extension = try extensions.decode(proto.Extension);
        var data = try extensions.vector(u16);
        const code = @intFromEnum(extension);
        for (seen[0..seen_len]) |s| if (s == code) return error.TlsDecodeError;
        if (seen_len == seen.len) return error.TlsDecodeError;
        seen[seen_len] = code;
        seen_len += 1;
        switch (extension) {
            .supported_versions => {
                var list = try data.vector(u8);
                while (!list.eof()) {
                    if (try list.decode(proto.Version) == .tls_1_3) supports_1_3 = true;
                }
            },
            .key_share => {
                has_key_share = true;
                var list = try data.vector(u16);
                while (!list.eof()) {
                    const group = try list.decode(proto.NamedGroup);
                    const share = try list.vectorBytes(u16);
                    hello.key_shares_offered += 1;
                    if (!handshake.groupSupported(group)) continue;
                    if (hello.shareFor(group) != null) return error.TlsIllegalParameter;
                    hello.key_shares[hello.key_shares_len] = .{ .group = group, .share = share };
                    hello.key_shares_len += 1;
                }
            },
            .supported_groups => {
                has_groups = true;
                var list = try data.vector(u16);
                if (list.eof()) return error.TlsDecodeError;
                while (!list.eof()) {
                    const group = try list.decode(proto.NamedGroup);
                    if (!handshake.groupSupported(group) or hello.supportsGroup(group)) continue;
                    hello.groups[hello.groups_len] = group;
                    hello.groups_len += 1;
                }
            },
            .signature_algorithms => {
                var list = try data.vector(u16);
                if (list.eof()) return error.TlsDecodeError;
                var n: usize = 0;
                while (!list.eof()) {
                    const scheme = try list.decode(proto.SignatureScheme);
                    if (std.mem.indexOfScalar(proto.SignatureScheme, &config.default_signature_schemes, scheme) == null) continue;
                    if (std.mem.indexOfScalar(proto.SignatureScheme, hello.schemes[0..n], scheme) != null) continue;
                    hello.schemes[n] = scheme;
                    n += 1;
                }
                hello.schemes_len = n;
            },
            .server_name => {
                var list = try data.vector(u16);
                while (!list.eof()) {
                    const name_type = try list.decode(u8);
                    var name = try list.vectorBytes(u16);
                    if (name_type != 0) continue;
                    if (hello.server_name != null) return error.TlsIllegalParameter;
                    // A host name only (RFC 6066 §3): no IP literal, no NUL,
                    // not empty, at most 255 bytes; one trailing dot is
                    // tolerated, as some clients send a FQDN.
                    if (name.len > 0 and name[name.len - 1] == '.') name = name[0 .. name.len - 1];
                    if (name.len == 0 or name.len > 255) return error.TlsIllegalParameter;
                    if (std.mem.indexOfScalar(u8, name, 0) != null) return error.TlsIllegalParameter;
                    // RFC 6066 forbids an IP literal here, but clients send
                    // one when told to connect to an address (wrk does), and
                    // every major stack lets it pass. It names no
                    // certificate, so it is treated as no name at all.
                    if (std.Io.net.IpAddress.parse(name, 0)) |_| continue else |_| {}
                    hello.server_name = name;
                }
            },
            // 0-RTT is not supported, and the client's early data could
            // not be skipped; Go refuses it the same way.
            .early_data => return error.TlsUnsupportedExtension,
            .application_layer_protocol_negotiation => {
                hello.alpn = try data.vectorBytes(u16);
                // Each name is 1 to 255 bytes, and there is at least one.
                var names = codec.Decoder.init(hello.alpn.?);
                if (names.eof()) return error.TlsDecodeError;
                while (!names.eof()) {
                    if ((try names.vectorBytes(u8)).len == 0) return error.TlsDecodeError;
                }
            },
            .certificate_authorities => {
                var list = try data.vector(u16);
                if (list.eof()) return error.TlsDecodeError;
                while (!list.eof()) {
                    if ((try list.vectorBytes(u16)).len == 0) return error.TlsDecodeError;
                }
            },
            // We never send a cookie, so none may come back.
            .cookie => hello.has_cookie = true,
            else => continue, // unknown or unused: skipped whole
        }
        try data.expectEof();
    }
    if (!supports_1_3) return error.TlsProtocolVersion;
    // (EC)DHE is the only key exchange here, so both are required, and
    // with no PSK so are signature algorithms (§9.2). Checked here, so a
    // second ClientHello meets them too.
    if (!has_key_share or !has_groups or hello.schemes_len == null) return error.TlsMissingExtension;
    // A share may only be offered for a group in supported_groups (§4.3.8).
    // Checked for the shares we could use; like Go, the others are ignored.
    for (hello.key_shares[0..hello.key_shares_len]) |ks| {
        if (!hello.supportsGroup(ks.group)) return error.TlsIllegalParameter;
    }
    return hello;
}

/// A ServerHello, or a HelloRetryRequest when `share` is null (§4.2.4).
fn writeServerHello(h: *Handshake, suite: proto.CipherSuite, group: proto.NamedGroup, share: ?[]const u8, session_id: []const u8) Error!void {
    var buf: [2048]u8 = undefined;
    var w = codec.Writer.init(&buf);
    buildServerHello(&w, suite, group, share, session_id) catch return error.TlsInternalError;
    try h.writeMessage(w.written());
}

fn buildServerHello(w: *codec.Writer, suite: proto.CipherSuite, group: proto.NamedGroup, share: ?[]const u8, session_id: []const u8) codec.Writer.Error!void {
    try w.enumValue(proto.HandshakeType.server_hello);
    const message = try w.beginLength(u24);
    try w.enumValue(proto.Version.tls_1_2);
    if (share != null) {
        var random: [32]u8 = undefined;
        crypto.rand.bytes(&random);
        try w.slice(&random);
    } else {
        try w.slice(&handshake.hello_retry_request_random);
    }
    try w.vector(u8, session_id);
    try w.enumValue(suite);
    try w.byte(0); // compression
    const extensions = try w.beginLength(u16);
    {
        try w.enumValue(proto.Extension.supported_versions);
        const ext = try w.beginLength(u16);
        try w.enumValue(proto.Version.tls_1_3);
        try ext.end(w);
    }
    {
        try w.enumValue(proto.Extension.key_share);
        const ext = try w.beginLength(u16);
        try w.enumValue(group);
        if (share) |s| try w.vector(u16, s);
        try ext.end(w);
    }
    try extensions.end(w);
    try message.end(w);
}

fn writeEncryptedExtensions(h: *Handshake, alpn: ?[]const u8) Error!void {
    var buf: [512]u8 = undefined;
    var w = codec.Writer.init(&buf);
    buildEncryptedExtensions(&w, alpn) catch return error.TlsInternalError;
    try h.writeMessage(w.written());
}

fn buildEncryptedExtensions(w: *codec.Writer, alpn: ?[]const u8) codec.Writer.Error!void {
    try w.enumValue(proto.HandshakeType.encrypted_extensions);
    const message = try w.beginLength(u24);
    const extensions = try w.beginLength(u16);
    if (alpn) |name| {
        try w.enumValue(proto.Extension.application_layer_protocol_negotiation);
        const ext = try w.beginLength(u16);
        const list = try w.beginLength(u16);
        try w.vector(u8, name);
        try list.end(w);
        try ext.end(w);
    }
    try extensions.end(w);
    try message.end(w);
}

fn writeCertificateRequest(h: *Handshake, verify_schemes: []const proto.SignatureScheme) Error!void {
    var buf: [128]u8 = undefined;
    var w = codec.Writer.init(&buf);
    buildCertificateRequest(&w, verify_schemes) catch return error.TlsInternalError;
    try h.writeMessage(w.written());
}

fn buildCertificateRequest(w: *codec.Writer, verify_schemes: []const proto.SignatureScheme) codec.Writer.Error!void {
    try w.enumValue(proto.HandshakeType.certificate_request);
    const message = try w.beginLength(u24);
    try w.vector(u8, &.{}); // certificate_request_context: none outside post-handshake auth
    const extensions = try w.beginLength(u16);
    try w.enumValue(proto.Extension.signature_algorithms);
    const ext = try w.beginLength(u16);
    try w.enumList(verify_schemes);
    try ext.end(w);
    try extensions.end(w);
    try message.end(w);
}

const testing = std.testing;
const data13 = @import("testdata/tls13.zig");

test "parsing the example ClientHello" {
    const hello = try parseClientHello(data13.client_hello[9..]);
    try testing.expectEqual(32, hello.session_id.len);
    try testing.expect(hello.offersSuite(.aes_256_gcm_sha384));
    try testing.expect(hello.offersSuite(.chacha20_poly1305_sha256));
    try testing.expect(!hello.offersSuite(@enumFromInt(0x1304)));
    try testing.expectEqualStrings("example.ulfheim.net", hello.server_name.?);
    try testing.expect(hello.supportsGroup(.x25519));
    try testing.expect(hello.supportsGroup(.secp384r1));
    try testing.expectEqualSlices(u8, &data13.client_public_key, hello.shareFor(.x25519).?);
    try testing.expectEqual(null, hello.shareFor(.secp256r1));
    try testing.expectEqual(null, hello.alpn);
    try testing.expect(hello.schemes_len.? > 0);
    try testing.expect(!hello.has_cookie);
}

/// A minimal ClientHello body for the parser: one suite, x25519 and no
/// share, so a retry would be needed.
fn testClientHello(buf: []u8, o: struct { version: proto.Version = .tls_1_2, name: ?[]const u8 = null, early_data: bool = false, schemes: bool = true }) ![]const u8 {
    var w = codec.Writer.init(buf);
    try w.enumValue(o.version);
    const zeros: [32]u8 = @splat(0);
    try w.slice(&zeros);
    try w.vector(u8, &.{});
    try w.vector(u16, &.{ 0x13, 0x01 });
    try w.vector(u8, &.{0});
    const ext = try w.beginLength(u16);
    try w.enumValue(proto.Extension.supported_versions);
    try w.vector(u16, &.{ 2, 3, 4 });
    try w.enumValue(proto.Extension.supported_groups);
    try w.vector(u16, &.{ 0, 2, 0, 0x1d });
    try w.enumValue(proto.Extension.key_share);
    try w.vector(u16, &.{ 0, 0 });
    if (o.schemes) {
        try w.enumValue(proto.Extension.signature_algorithms);
        try w.vector(u16, &.{ 0, 2, 0x04, 0x03 });
    }
    if (o.name) |name| {
        try w.enumValue(proto.Extension.server_name);
        const sni = try w.beginLength(u16);
        const list = try w.beginLength(u16);
        try w.byte(0);
        try w.vector(u16, name);
        try list.end(&w);
        try sni.end(&w);
    }
    if (o.early_data) {
        try w.enumValue(proto.Extension.early_data);
        try w.vector(u16, &.{});
    }
    try ext.end(&w);
    return w.written();
}

test "server names: a trailing dot is dropped, IP literals and NULs are refused" {
    var buf: [512]u8 = undefined;
    try testing.expectEqualStrings("example.com", (try parseClientHello(try testClientHello(&buf, .{ .name = "example.com." }))).server_name.?);
    try testing.expectEqualStrings("example.com", (try parseClientHello(try testClientHello(&buf, .{ .name = "example.com" }))).server_name.?);
    try testing.expectEqual(null, (try parseClientHello(try testClientHello(&buf, .{ .name = "10.0.0.1" }))).server_name);
    try testing.expectEqual(null, (try parseClientHello(try testClientHello(&buf, .{ .name = "::1" }))).server_name);
    try testing.expectError(error.TlsIllegalParameter, parseClientHello(try testClientHello(&buf, .{ .name = "exa\x00mple.com" })));
    try testing.expectError(error.TlsIllegalParameter, parseClientHello(try testClientHello(&buf, .{ .name = "." })));
}

test "legacy_version above SSL 3.0 is ignored, early_data is refused, signature_algorithms is required" {
    var buf: [512]u8 = undefined;
    try testing.expectError(error.TlsMissingExtension, parseClientHello(try testClientHello(&buf, .{ .schemes = false })));
    try testing.expectError(error.TlsProtocolVersion, parseClientHello(try testClientHello(&buf, .{ .version = @enumFromInt(0x0300) })));
    _ = try parseClientHello(try testClientHello(&buf, .{ .version = @enumFromInt(0x0301) }));
    _ = try parseClientHello(try testClientHello(&buf, .{ .version = .tls_1_3 }));
    try testing.expectError(error.TlsUnsupportedExtension, parseClientHello(try testClientHello(&buf, .{ .early_data = true })));
}

test "ALPN selection follows the server's order and refuses an offer with nothing in common" {
    const offer = "\x02h2\x08http/1.1";
    try testing.expectEqualStrings("http/1.1", (try selectAlpn(&.{ "http/1.1", "h2" }, offer)).?);
    try testing.expectEqualStrings("h2", (try selectAlpn(&.{ "h2", "http/1.1" }, offer)).?);
    try testing.expectError(error.TlsNoApplicationProtocol, selectAlpn(&.{"spdy/3"}, offer));
    try testing.expectEqual(null, try selectAlpn(&.{"h2"}, null));
    try testing.expectEqual(null, try selectAlpn(&.{}, offer));
    try testing.expectError(error.TlsIllegalParameter, selectAlpn(&.{"h2"}, "\x00"));
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
