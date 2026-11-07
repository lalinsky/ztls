//! The server's side of the handshake (RFC 8446 §2): the ClientHello, a
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
    var h = Handshake.init(conn, options.allocator, options.max_handshake_message_len);
    defer h.deinit();
    handshakeInner(&h, options) catch |err| {
        h.sendAlert(err);
        return err;
    };
}

/// What a ClientHello offers. Slices point into the message.
const ClientHello = struct {
    session_id: []const u8,
    /// The cipher_suites vector, raw.
    suites: []const u8,
    key_shares: [max_key_shares]KeyShare = undefined,
    key_shares_len: usize = 0,
    groups: [max_groups]proto.NamedGroup = undefined,
    groups_len: usize = 0,
    schemes: [max_schemes]proto.SignatureScheme = undefined,
    schemes_len: ?usize = null,
    server_name: ?[]const u8 = null,
    /// The ProtocolNameList, raw, if ALPN was offered.
    alpn: ?[]const u8 = null,
    has_cookie: bool = false,

    const max_key_shares = 8;
    const max_groups = 32;
    const max_schemes = 64;

    const KeyShare = struct {
        group: proto.NamedGroup,
        share: []const u8,
    };

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
    const auth = opt.auth orelse return error.TlsInternalError;
    if (opt.cipher_suites.len == 0 or opt.named_groups.len == 0) return error.TlsInternalError;

    var msg = try h.nextMessage();
    try h.expect(msg, .client_hello);
    var hello = try parseClientHello(msg.body);
    var choices = try choose(&hello, opt, auth);
    h.setSuite(choices.suite);
    h.hashMessage(msg);

    const compat = hello.session_id.len > 0;
    var session_id_buf: [32]u8 = undefined;
    @memcpy(session_id_buf[0..hello.session_id.len], hello.session_id);
    const session_id = session_id_buf[0..hello.session_id.len];

    var retried = false;
    if (hello.shareFor(choices.group) == null) {
        // No usable share: ask for one (§4.1.4).
        retried = true;
        h.transcript.replaceWithMessageHash();
        try writeServerHello(h, choices.suite, choices.group, null, session_id);
        if (compat) h.conn.writeChangeCipherSpec() catch return error.WriteFailed;
        try h.flush();

        msg = try h.nextMessage();
        try h.expect(msg, .client_hello);
        hello = try parseClientHello(msg.body);
        const second = try choose(&hello, opt, auth);
        // The second hello may differ only in its key share (§4.1.2).
        if (second.suite != choices.suite or second.group != choices.group or second.scheme != choices.scheme) return error.TlsIllegalParameter;
        if (!std.mem.eql(u8, hello.session_id, session_id) or hello.has_cookie) return error.TlsIllegalParameter;
        if (hello.key_shares_len != 1 or hello.shareFor(choices.group) == null) return error.TlsIllegalParameter;
        choices = second;
        h.hashMessage(msg);
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
    if (compat and !retried) h.conn.writeChangeCipherSpec() catch return error.WriteFailed;

    try writeEncryptedExtensions(h, choices.alpn);
    if (opt.client_auth != null) try writeCertificateRequest(h);
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
            try h.verifyChain(peer, client_auth.root_ca, .client, null, opt.now.toSeconds());
            h.hashMessage(msg);
            msg = try h.nextMessage();
            try h.expect(msg, .certificate_verify);
            try h.verifyCertificateVerify(msg.body, &peer.public_key, .client);
            h.hashMessage(msg);
        } else {
            if (client_auth.auth_type == .require) return error.TlsCertificateRequired;
            h.hashMessage(msg);
        }
        msg = try h.nextMessage();
    }
    try h.expect(msg, .finished);
    try h.verifyFinished(msg.body, &hs.client);
    h.hashMessage(msg);

    try h.installReadKeys(ap.client);
    h.conn.read.in_handshake = false;
    h.conn.alpn_protocol = choices.alpn;
    h.conn.strict_close_notify = opt.strict_close_notify;
}

/// Picks the suite, group, signature scheme and ALPN protocol, or says
/// why no handshake is possible.
fn choose(hello: *const ClientHello, opt: config.Server, auth: *const config.CertKeyPair) Error!Choices {
    const suite = for (opt.cipher_suites) |suite| {
        if (hello.offersSuite(suite)) break suite;
    } else return error.TlsHandshakeFailure;

    // Of the groups the client sent shares for, our favourite; failing
    // that, our favourite among the ones it supports, via a retry.
    const group = for (opt.named_groups) |group| {
        if (handshake.groupSupported(group) and hello.shareFor(group) != null) break group;
    } else for (opt.named_groups) |group| {
        if (handshake.groupSupported(group) and hello.supportsGroup(group)) break group;
    } else return error.TlsHandshakeFailure;

    const schemes = hello.schemes[0 .. hello.schemes_len orelse return error.TlsMissingExtension];
    const scheme = handshake.selectScheme(auth.key.key_type, schemes) orelse return error.TlsHandshakeFailure;

    return .{ .suite = suite, .group = group, .scheme = scheme, .alpn = try selectAlpn(opt.alpn_protocols, hello.alpn) };
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
    var d = codec.Decoder.init(body);
    if (try d.decode(proto.Version) != .tls_1_2) return error.TlsProtocolVersion;
    _ = try d.array(32); // random
    const session_id = try d.vectorBytes(u8);
    if (session_id.len > 32) return error.TlsIllegalParameter;
    const suites = try d.vectorBytes(u16);
    if (suites.len == 0 or suites.len % 2 != 0) return error.TlsDecodeError;
    // TLS 1.3 clients offer the null compression method only (§4.1.2).
    if (!std.mem.eql(u8, try d.vectorBytes(u8), &.{0})) return error.TlsIllegalParameter;
    var extensions = try d.vector(u16);
    try d.expectEof();

    var hello: ClientHello = .{ .session_id = session_id, .suites = suites };
    var supports_1_3 = false;
    // One bit per extension type we know; a repeated one is a violation.
    var seen: u64 = 0;
    while (!extensions.eof()) {
        const extension = try extensions.decode(proto.Extension);
        var data = try extensions.vector(u16);
        const code = @intFromEnum(extension);
        if (code < 64) {
            const bit = @as(u64, 1) << @intCast(code);
            if (seen & bit != 0) return error.TlsIllegalParameter;
            seen |= bit;
        }
        switch (extension) {
            .supported_versions => {
                var list = try data.vector(u8);
                while (!list.eof()) {
                    if (try list.decode(proto.Version) == .tls_1_3) supports_1_3 = true;
                }
            },
            .key_share => {
                var list = try data.vector(u16);
                while (!list.eof()) {
                    const group = try list.decode(proto.NamedGroup);
                    const share = try list.vectorBytes(u16);
                    if (hello.shareFor(group) != null) return error.TlsIllegalParameter;
                    if (hello.key_shares_len < hello.key_shares.len) {
                        hello.key_shares[hello.key_shares_len] = .{ .group = group, .share = share };
                        hello.key_shares_len += 1;
                    }
                }
            },
            .supported_groups => {
                var list = try data.vector(u16);
                if (list.eof()) return error.TlsDecodeError;
                while (!list.eof()) {
                    const group = try list.decode(proto.NamedGroup);
                    if (hello.groups_len < hello.groups.len) {
                        hello.groups[hello.groups_len] = group;
                        hello.groups_len += 1;
                    }
                }
            },
            .signature_algorithms => {
                var list = try data.vector(u16);
                if (list.eof()) return error.TlsDecodeError;
                var n: usize = 0;
                while (!list.eof()) {
                    const scheme = try list.decode(proto.SignatureScheme);
                    if (n < hello.schemes.len) {
                        hello.schemes[n] = scheme;
                        n += 1;
                    }
                }
                hello.schemes_len = n;
            },
            .server_name => {
                var list = try data.vector(u16);
                while (!list.eof()) {
                    const name_type = try list.decode(u8);
                    const name = try list.vectorBytes(u16);
                    if (name_type == 0) {
                        if (name.len == 0 or hello.server_name != null) return error.TlsIllegalParameter;
                        hello.server_name = name;
                    }
                }
            },
            .application_layer_protocol_negotiation => {
                hello.alpn = try data.vectorBytes(u16);
                if (hello.alpn.?.len == 0) return error.TlsDecodeError;
            },
            // We never send a cookie, so none may come back.
            .cookie => hello.has_cookie = true,
            else => continue, // unknown or unused: skipped whole
        }
        try data.expectEof();
    }
    if (!supports_1_3) return error.TlsProtocolVersion;
    if (hello.key_shares_len == 0 and hello.groups_len == 0) return error.TlsMissingExtension;
    return hello;
}

/// A ServerHello, or a HelloRetryRequest when `share` is null (§4.1.4).
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

fn writeCertificateRequest(h: *Handshake) Error!void {
    var buf: [128]u8 = undefined;
    var w = codec.Writer.init(&buf);
    buildCertificateRequest(&w) catch return error.TlsInternalError;
    try h.writeMessage(w.written());
}

fn buildCertificateRequest(w: *codec.Writer) codec.Writer.Error!void {
    try w.enumValue(proto.HandshakeType.certificate_request);
    const message = try w.beginLength(u24);
    try w.vector(u8, &.{}); // certificate_request_context: none outside post-handshake auth
    const extensions = try w.beginLength(u16);
    try w.enumValue(proto.Extension.signature_algorithms);
    const ext = try w.beginLength(u16);
    try w.enumList(&handshake.signature_algorithms);
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

test "ALPN selection follows the server's order and refuses an offer with nothing in common" {
    const offer = "\x02h2\x08http/1.1";
    try testing.expectEqualStrings("http/1.1", (try selectAlpn(&.{ "http/1.1", "h2" }, offer)).?);
    try testing.expectEqualStrings("h2", (try selectAlpn(&.{ "h2", "http/1.1" }, offer)).?);
    try testing.expectError(error.TlsNoApplicationProtocol, selectAlpn(&.{"spdy/3"}, offer));
    try testing.expectEqual(null, try selectAlpn(&.{"h2"}, null));
    try testing.expectEqual(null, try selectAlpn(&.{}, offer));
    try testing.expectError(error.TlsIllegalParameter, selectAlpn(&.{"h2"}, "\x00"));
}
