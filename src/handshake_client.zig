//! The client's side of the handshake (RFC 9846 §2): ClientHello, a
//! HelloRetryRequest if the server wants another group, the server's
//! flight, then our Finished (and certificate, if asked). A TLS 1.2
//! ServerHello hands over to `handshake_client_tls12.zig`.

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
const tls12 = @import("handshake_client_tls12.zig");

pub fn run(conn: *Connection, options: config.Client) Error!void {
    try checkOptions(options);
    var h = Handshake.init(conn, options.allocator, options.max_handshake_message_len);
    defer h.deinit();
    handshakeInner(&h, options) catch |err| {
        h.sendAlert(err);
        return err;
    };
}

/// A ServerHello of either version.
const AnyServerHello = union(enum) {
    tls13: ServerHello,
    tls12: tls12.ServerHello,
};

/// What a TLS 1.3 ServerHello or HelloRetryRequest tells us.
const ServerHello = struct {
    is_retry: bool,
    suite: proto.CipherSuite,
    /// The server's share, or in a HelloRetryRequest the group it wants a
    /// share for; a retry may instead carry only a cookie.
    key_share: ?KeyShare,
    cookie: ?[]const u8 = null,

    const KeyShare = struct {
        group: proto.NamedGroup,
        share: []const u8,
    };
};

const CertificateRequest = struct {
    context_buf: [255]u8,
    context_len: u8,
    /// The scheme our certificate can answer with, if any.
    scheme: ?proto.SignatureScheme,

    fn context(r: *const CertificateRequest) []const u8 {
        return r.context_buf[0..r.context_len];
    }
};

/// Misconfiguration is ours, not the peer's: nothing is sent for it, not
/// even an alert. An empty host would leave the certificate's name
/// unchecked, which only insecure_skip_verify may ask for.
fn checkOptions(opt: config.Client) error{TlsInternalError}!void {
    if (opt.root_ca == null and !opt.insecure_skip_verify) return error.TlsInternalError;
    if (opt.host.len == 0 and !opt.insecure_skip_verify) return error.TlsInternalError;
    if (opt.named_groups.len == 0) return error.TlsInternalError;
    if (!offers(opt, .tls_1_3) and !offers(opt, .tls_1_2)) return error.TlsInternalError;
    if (offers(opt, .tls_1_3)) {
        if (opt.key_shares.len == 0) return error.TlsInternalError;
        for (opt.key_shares) |group| {
            if (std.mem.indexOfScalar(proto.NamedGroup, opt.named_groups, group) == null) return error.TlsInternalError;
        }
    }
}

/// Whether `cipher_suites` offers `version`: it does with any of its suites.
fn offers(opt: config.Client, version: proto.Version) bool {
    for (opt.cipher_suites) |suite| {
        if (suite.version() == version) return true;
    }
    return false;
}

fn handshakeInner(h: *Handshake, opt: config.Client) Error!void {
    var random: [32]u8 = undefined;
    crypto.rand.bytes(&random);
    // A non-empty legacy_session_id asks the server for middlebox
    // compatibility mode (§E.4); both sides then send a dummy CCS. With
    // TLS 1.2 alone it would ask to resume a session, so none is sent.
    var session_id_buf: [32]u8 = undefined;
    crypto.rand.bytes(&session_id_buf);
    const session_id: []const u8 = if (offers(opt, .tls_1_3)) &session_id_buf else &.{};

    var shares: KeyShares = if (offers(opt, .tls_1_3)) try KeyShares.generate(opt.key_shares) else .{};
    defer shares.deinit();
    // A TLS 1.2 client certificate signs the messages themselves.
    if (offers(opt, .tls_1_2) and opt.auth != null) h.keepRawTranscript();
    h.record_version = @enumFromInt(0x0301);
    try writeClientHello(h, opt, &random, session_id, &shares, opt.key_shares, null);
    h.record_version = .tls_1_2;
    try h.flush();
    // A server that may answer TLS 1.2 sends no compatibility CCS, and may
    // send warning alerts before it says which version it speaks.
    h.ccs_allowed = !offers(opt, .tls_1_2);
    h.tolerate_warnings = offers(opt, .tls_1_2);

    var msg = try h.nextMessage();
    try h.expect(msg, .server_hello);
    var hello = switch (try parseServerHello(msg.body, opt, session_id)) {
        .tls13 => |hello| hello,
        .tls12 => |hello| {
            h.setSuite(hello.suite);
            try h.hashMessage(msg);
            try tls12.run(h, opt, &random, hello);
            h.conn.setServerName(if (sendsSni(opt.host)) opt.host else null);
            return;
        },
    };
    h.ccs_allowed = true;
    h.tolerate_warnings = false;
    h.dropRawTranscript();
    var sent_ccs = false;
    if (hello.is_retry) {
        try h.expectFlightEnd();
        h.conn.retried = true;
        h.setSuite(hello.suite);
        h.transcript.replaceWithMessageHash();
        try h.hashMessage(msg);
        // A retry must change something (§4.2.4): a group we support and
        // did not already offer a share for, or a cookie to echo.
        var retry_groups: [1]proto.NamedGroup = undefined;
        var share_groups: []const proto.NamedGroup = opt.key_shares;
        if (hello.key_share) |ks| {
            if (std.mem.indexOfScalar(proto.NamedGroup, opt.named_groups, ks.group) == null) return error.TlsIllegalParameter;
            if (!handshake.groupSupported(ks.group) or shares.has(ks.group)) return error.TlsIllegalParameter;
            retry_groups = .{ks.group};
            share_groups = &retry_groups;
            shares.deinit();
            shares = try KeyShares.generate(share_groups);
        } else if (hello.cookie == null) {
            return error.TlsIllegalParameter;
        }

        h.conn.writeChangeCipherSpec() catch return error.WriteFailed;
        sent_ccs = true;
        try writeClientHello(h, opt, &random, session_id, &shares, share_groups, hello.cookie);
        try h.flush();

        msg = try h.nextMessage();
        try h.expect(msg, .server_hello);
        // The version is settled, so a ServerHello that does not say
        // 0x0303 is malformed now rather than another version, as AWS-LC
        // has it.
        if (msg.body.len >= 2 and std.mem.readInt(u16, msg.body[0..2], .big) != @intFromEnum(proto.Version.tls_1_2)) return error.TlsDecodeError;
        const second = switch (try parseServerHello(msg.body, opt, session_id)) {
            .tls13 => |second| second,
            // A retry settled TLS 1.3 (§4.2.4).
            .tls12 => return error.TlsIllegalParameter,
        };
        if (second.is_retry) return error.TlsUnexpectedMessage;
        if (second.suite != hello.suite) return error.TlsIllegalParameter;
        hello = second;
    } else {
        h.setSuite(hello.suite);
    }
    try h.hashMessage(msg);

    const key_share = hello.key_share orelse return error.TlsMissingExtension;
    if (!shares.has(key_share.group)) return error.TlsIllegalParameter;
    h.conn.group = key_share.group;
    var secret_buf: [KeyShares.max_secret_len]u8 = undefined;
    defer std.crypto.secureZero(u8, &secret_buf);
    const shared_secret = try shares.sharedSecret(key_share.group, key_share.share, &secret_buf);
    var hs = h.deriveHandshakeSecrets(shared_secret);
    defer hs.wipe();
    try h.installReadKeys(hs.server);
    // From here everything we send, an alert included, is protected with
    // our handshake keys (§5), and the dummy CCS goes ahead of it.
    if (!sent_ccs) h.conn.writeChangeCipherSpec() catch return error.WriteFailed;
    try h.installWriteKeys(hs.client);

    msg = try h.nextMessage();
    try h.expect(msg, .encrypted_extensions);
    const alpn = try parseEncryptedExtensions(msg.body, opt);
    try h.hashMessage(msg);

    msg = try h.nextMessage();
    var request: ?CertificateRequest = null;
    if (msg.handshake_type == .certificate_request) {
        request = try parseCertificateRequest(msg.body, opt.auth);
        try h.hashMessage(msg);
        msg = try h.nextMessage();
    }

    try h.expect(msg, .certificate);
    // A server's chain is never empty (§4.5.1).
    var peer = (try h.parseCertificate(msg.body, "")) orelse return error.TlsDecodeError;
    defer peer.deinit();
    h.conn.peer_key_type = peer.public_key.key_type;
    if (!opt.insecure_skip_verify) {
        try h.verifyChain(&peer, opt.root_ca.?, .server, opt.host, opt.now.toSeconds());
    }
    try h.hashMessage(msg);

    msg = try h.nextMessage();
    try h.expect(msg, .certificate_verify);
    try h.verifyCertificateVerify(msg.body, &peer.public_key, .server);
    try h.hashMessage(msg);

    msg = try h.nextMessage();
    try h.expect(msg, .finished);
    try h.expectFlightEnd();
    try h.verifyFinished(msg.body, &hs.server);
    try h.hashMessage(msg);

    var ap = h.deriveApplicationSecrets();
    defer ap.wipe();

    // Our flight.
    if (request) |req| {
        if (opt.auth != null and req.scheme != null) {
            try h.writeCertificate(req.context(), opt.auth.?);
            try h.writeCertificateVerify(opt.auth.?, req.scheme.?, .client);
        } else {
            // Nothing to show: an empty Certificate (§4.5.1).
            try h.writeCertificate(req.context(), null);
        }
    }
    try h.writeFinished(&hs.client);
    try h.flush();

    try h.installReadKeys(ap.server);
    try h.installWriteKeys(ap.client);
    h.conn.read.ccs = .refuse;
    h.conn.alpn_protocol = alpn;
    h.conn.setServerName(if (sendsSni(opt.host)) opt.host else null);
    h.conn.strict_close_notify = opt.strict_close_notify;
}

/// Whether `host` is an IP literal, which gets no SNI (RFC 6066 §3).
fn isIpLiteral(host: []const u8) bool {
    _ = std.Io.net.IpAddress.parse(host, 0) catch return false;
    return true;
}

/// Whether `host` goes out as SNI: a non-empty name that is not an
/// IP literal.
fn sendsSni(host: []const u8) bool {
    return host.len != 0 and !isIpLiteral(host);
}

fn writeClientHello(
    h: *Handshake,
    opt: config.Client,
    random: *const [32]u8,
    session_id: []const u8,
    shares: *const KeyShares,
    share_groups: []const proto.NamedGroup,
    cookie: ?[]const u8,
) Error!void {
    var buf: [8192]u8 = undefined;
    var w = codec.Writer.init(&buf);
    build(&w, opt, random, session_id, shares, share_groups, cookie) catch return error.TlsInternalError;
    try h.writeMessage(w.written());
}

fn build(
    w: *codec.Writer,
    opt: config.Client,
    random: *const [32]u8,
    session_id: []const u8,
    shares: *const KeyShares,
    share_groups: []const proto.NamedGroup,
    cookie: ?[]const u8,
) codec.Writer.Error!void {
    try w.enumValue(proto.HandshakeType.client_hello);
    const message = try w.beginLength(u24);
    try w.enumValue(proto.Version.tls_1_2);
    try w.slice(random);
    try w.vector(u8, session_id);
    {
        const suites = try w.beginLength(u16);
        for (opt.cipher_suites) |suite| try w.enumValue(suite);
        // Secure renegotiation (RFC 5746 §3.4), which we never do: the
        // signal that we would refuse it safely.
        if (offers(opt, .tls_1_2)) try w.enumValue(proto.CipherSuite.empty_renegotiation_info_scsv);
        try suites.end(w);
    }
    try w.vector(u8, &.{0}); // legacy_compression_methods: null only
    const extensions = try w.beginLength(u16);
    if (sendsSni(opt.host)) {
        try w.enumValue(proto.Extension.server_name);
        const ext = try w.beginLength(u16);
        const list = try w.beginLength(u16);
        try w.byte(0); // host_name
        try w.vector(u16, opt.host);
        try list.end(w);
        try ext.end(w);
    }
    {
        try w.enumValue(proto.Extension.supported_groups);
        const ext = try w.beginLength(u16);
        // The hybrid is TLS 1.3's alone.
        const list = try w.beginLength(u16);
        for (opt.named_groups) |group| {
            if (group == .x25519_ml_kem768 and !offers(opt, .tls_1_3)) continue;
            try w.enumValue(group);
        }
        try list.end(w);
        try ext.end(w);
    }
    {
        try w.enumValue(proto.Extension.signature_algorithms);
        const ext = try w.beginLength(u16);
        try w.enumList(&handshake.signature_algorithms);
        try ext.end(w);
    }
    if (offers(opt, .tls_1_3)) {
        try w.enumValue(proto.Extension.supported_versions);
        const ext = try w.beginLength(u16);
        const list = try w.beginLength(u8);
        try w.enumValue(proto.Version.tls_1_3);
        if (offers(opt, .tls_1_2)) try w.enumValue(proto.Version.tls_1_2);
        try list.end(w);
        try ext.end(w);
    }
    if (offers(opt, .tls_1_2)) {
        // Uncompressed points only (RFC 8422 §5.1.2).
        try w.enumValue(proto.Extension.ec_point_formats);
        try w.vector(u16, &.{ 1, 0 });
        try w.enumValue(proto.Extension.extended_master_secret);
        try w.vector(u16, &.{});
    }
    if (opt.alpn_protocols.len > 0) {
        try w.enumValue(proto.Extension.application_layer_protocol_negotiation);
        const ext = try w.beginLength(u16);
        const list = try w.beginLength(u16);
        for (opt.alpn_protocols) |name| try w.vector(u8, name);
        try list.end(w);
        try ext.end(w);
    }
    if (offers(opt, .tls_1_3)) {
        try w.enumValue(proto.Extension.key_share);
        const ext = try w.beginLength(u16);
        const list = try w.beginLength(u16);
        for (share_groups) |group| {
            var share_buf: [KeyShares.max_share_len]u8 = undefined;
            try w.enumValue(group);
            try w.vector(u16, shares.publicShare(group, &share_buf));
        }
        try list.end(w);
        try ext.end(w);
    }
    if (cookie) |c| {
        try w.enumValue(proto.Extension.cookie);
        const ext = try w.beginLength(u16);
        try w.vector(u16, c);
        try ext.end(w);
    }
    try extensions.end(w);
    try message.end(w);
}

/// The last eight bytes of a ServerHello.random from a server that could
/// have spoken TLS 1.3 and chose TLS 1.2, or something older
/// (RFC 9846 §4.2.3).
const downgrade_tls12 = "DOWNGRD\x01";
const downgrade_tls11 = "DOWNGRD\x00";

fn parseServerHello(body: []const u8, opt: config.Client, session_id: []const u8) Error!AnyServerHello {
    var d = codec.Decoder.init(body);
    const legacy_version = try d.decode(proto.Version);
    const random = (try d.array(32)).*;
    const echoed_session_id = try d.vectorBytes(u8);
    if (echoed_session_id.len > 32) return error.TlsDecodeError;
    const suite = try d.decode(proto.CipherSuite);
    if (try d.decode(u8) != 0) return error.TlsIllegalParameter; // compression
    // A TLS 1.2 ServerHello may stop before the extensions.
    var extensions = if (d.eof()) codec.Decoder.init(&.{}) else try d.vector(u16);
    try d.expectEof();

    // Only supported_versions says TLS 1.3 (§4.2.1); without it,
    // legacy_version says what is spoken, and only TLS 1.2 is spoken so.
    var version: proto.Version = if (legacy_version == .tls_1_2) .tls_1_2 else return error.TlsProtocolVersion;
    var scan = extensions;
    while (!scan.eof()) {
        const extension = try scan.decode(proto.Extension);
        var data = try scan.vector(u16);
        if (extension == .supported_versions) {
            // Only in answer to ours, and only for TLS 1.3.
            if (!offers(opt, .tls_1_3)) return error.TlsUnsupportedExtension;
            if (try data.decode(proto.Version) != .tls_1_3) return error.TlsIllegalParameter;
            try data.expectEof();
            version = .tls_1_3;
        }
    }
    if (!offers(opt, version)) return error.TlsProtocolVersion;
    // One of ours, and one of the version's.
    if (std.mem.indexOfScalar(proto.CipherSuite, opt.cipher_suites, suite) == null) return error.TlsIllegalParameter;
    if (suite.version() != version) return error.TlsIllegalParameter;

    if (version == .tls_1_2) return .{ .tls12 = try parseServerHelloTls12(opt, random, session_id, echoed_session_id, suite, extensions) };

    const is_retry = std.mem.eql(u8, &random, &handshake.hello_retry_request_random);
    if (!std.mem.eql(u8, echoed_session_id, session_id)) return error.TlsIllegalParameter;
    var hello: ServerHello = .{ .is_retry = is_retry, .suite = suite, .key_share = null };
    // (BoringSSL's runner wants illegal_parameter for a retry's duplicate.)
    try checkNoDuplicates(extensions, if (is_retry) error.TlsIllegalParameter else error.TlsDecodeError);
    while (!extensions.eof()) {
        const extension = try extensions.decode(proto.Extension);
        var data = try extensions.vector(u16);
        switch (extension) {
            .supported_versions => continue, // read above
            .key_share => {
                const group = try data.decode(proto.NamedGroup);
                hello.key_share = .{ .group = group, .share = if (is_retry) &.{} else try data.vectorBytes(u16) };
            },
            .cookie => {
                if (!is_retry) return error.TlsIllegalParameter;
                hello.cookie = try data.vectorBytes(u16);
                if (hello.cookie.?.len == 0) return error.TlsDecodeError;
            },
            // We offered no PSK, so nothing else belongs here (§4.2.3).
            else => return error.TlsUnsupportedExtension,
        }
        try data.expectEof();
    }
    return .{ .tls13 = hello };
}

/// The rest of a TLS 1.2 ServerHello: the downgrade sentinel, no
/// resumption, and the extensions TLS 1.2 puts here.
fn parseServerHelloTls12(opt: config.Client, random: [32]u8, session_id: []const u8, echoed_session_id: []const u8, suite: proto.CipherSuite, extensions: codec.Decoder) Error!tls12.ServerHello {
    // A server that could speak TLS 1.3 and chose an older version has
    // been tampered with, when we offered 1.3 (§4.2.3).
    if (offers(opt, .tls_1_3)) {
        if (std.mem.eql(u8, random[24..], downgrade_tls12) or std.mem.eql(u8, random[24..], downgrade_tls11)) return error.TlsIllegalParameter;
    }
    // Our TLS 1.3 session ID back would be resuming a session we never
    // offered; BoringSSL refuses it, and its runner checks that.
    if (session_id.len > 0 and std.mem.eql(u8, echoed_session_id, session_id)) return error.TlsIllegalParameter;

    var hello: tls12.ServerHello = .{ .suite = suite, .random = random };
    try checkNoDuplicates(extensions, error.TlsDecodeError);
    var d = extensions;
    while (!d.eof()) {
        const extension = try d.decode(proto.Extension);
        var data = try d.vector(u16);
        switch (extension) {
            // Secure renegotiation acknowledged: with nothing to
            // renegotiate yet, renegotiated_connection is empty (RFC 5746
            // §3.4). A server that sends none is accepted, as AWS-LC and
            // s2n do; we never renegotiate either way.
            .renegotiation_info => {
                if (!std.mem.eql(u8, data.rest(), &.{0})) return error.TlsHandshakeFailure;
                continue;
            },
            .extended_master_secret => hello.extended_master_secret = true,
            // If sent, it must allow uncompressed points (RFC 8422 §5.2).
            .ec_point_formats => {
                const formats = try data.vectorBytes(u8);
                if (formats.len == 0) return error.TlsDecodeError;
                if (std.mem.indexOfScalar(u8, formats, 0) == null) return error.TlsIllegalParameter;
            },
            .application_layer_protocol_negotiation => hello.alpn = try parseAlpn(&data, opt),
            .server_name => if (!sendsSni(opt.host)) return error.TlsUnsupportedExtension,
            // Not allowed here, but sent by some servers, so tolerated as
            // AWS-LC does.
            .supported_groups => continue,
            // Nothing else was offered for TLS 1.2: no session tickets, no
            // status_request.
            else => return error.TlsUnsupportedExtension,
        }
        try data.expectEof();
    }
    return hello;
}

/// A repeated extension type is a malformed block (§4.3), whatever the
/// type, so the whole block is checked before any extension is read.
/// Servers send a handful of extensions, so a block past the list is
/// taken as malformed too.
fn checkNoDuplicates(extensions: codec.Decoder, err: Error) Error!void {
    var d = extensions;
    var codes: [32]u16 = undefined;
    var len: usize = 0;
    while (!d.eof()) {
        const code = @intFromEnum(try d.decode(proto.Extension));
        _ = try d.vector(u16);
        for (codes[0..len]) |c| if (c == code) return err;
        if (len == codes.len) return err;
        codes[len] = code;
        len += 1;
    }
}

/// Returns the ALPN protocol the server chose, as our own slice.
fn parseEncryptedExtensions(body: []const u8, opt: config.Client) Error!?[]const u8 {
    var d = codec.Decoder.init(body);
    var extensions = try d.vector(u16);
    try d.expectEof();
    var alpn: ?[]const u8 = null;
    try checkNoDuplicates(extensions, error.TlsDecodeError);
    while (!extensions.eof()) {
        const extension = try extensions.decode(proto.Extension);
        var data = try extensions.vector(u16);
        switch (extension) {
            .application_layer_protocol_negotiation => alpn = try parseAlpn(&data, opt),
            // An acknowledgement of our SNI, which must have been sent.
            .server_name => if (!sendsSni(opt.host)) return error.TlsUnsupportedExtension,
            // The server's preferences, for a later connection.
            .supported_groups => {},
            else => return error.TlsUnsupportedExtension,
        }
        if (extension != .supported_groups) try data.expectEof();
    }
    return alpn;
}

/// The server's ALPN choice, which must be one protocol we offered;
/// returned as our own slice.
fn parseAlpn(data: *codec.Decoder, opt: config.Client) Error![]const u8 {
    if (opt.alpn_protocols.len == 0) return error.TlsUnsupportedExtension;
    var list = try data.vector(u16);
    const name = try list.vectorBytes(u8);
    try list.expectEof();
    for (opt.alpn_protocols) |ours| {
        if (std.mem.eql(u8, ours, name)) return ours;
    }
    // Not something we offered.
    return error.TlsIllegalParameter;
}

fn parseCertificateRequest(body: []const u8, auth: ?*const config.CertKeyPair) Error!CertificateRequest {
    var d = codec.Decoder.init(body);
    const context = try d.vectorBytes(u8);
    var extensions = try d.vector(u16);
    try d.expectEof();

    // The context is for post-handshake authentication only (§4.4.2).
    if (context.len != 0) return error.TlsDecodeError;
    var request: CertificateRequest = .{ .context_buf = undefined, .context_len = 0, .scheme = null };

    var offered: [64]proto.SignatureScheme = undefined;
    var offered_len: ?usize = null;
    try checkNoDuplicates(extensions, error.TlsDecodeError);
    while (!extensions.eof()) {
        const extension = try extensions.decode(proto.Extension);
        var data = try extensions.vector(u16);
        switch (extension) {
            .signature_algorithms => {
                var list = try data.vector(u16);
                try data.expectEof();
                var n: usize = 0;
                while (!list.eof()) {
                    const scheme = try list.decode(proto.SignatureScheme);
                    if (n < offered.len) {
                        offered[n] = scheme;
                        n += 1;
                    }
                }
                offered_len = n;
            },
            .certificate_authorities => {
                var list = try data.vector(u16);
                try data.expectEof();
                if (list.eof()) return error.TlsDecodeError;
                while (!list.eof()) {
                    if ((try list.vectorBytes(u16)).len == 0) return error.TlsDecodeError;
                }
            },
            // oid_filters and the rest only narrow what the server would
            // like; we offer what we have.
            else => {},
        }
    }
    const n = offered_len orelse return error.TlsMissingExtension;
    if (auth) |pair| request.scheme = handshake.selectScheme(pair.key.key_type, offered[0..n], .tls13);
    return request;
}

const testing = std.testing;

test "a ServerHello must echo the session id and name TLS 1.3" {
    const opt: config.Client = .{ .allocator = testing.allocator, .host = "localhost", .insecure_skip_verify = true, .now = undefined };
    var session_id: [32]u8 = @splat(7);
    var buf: [256]u8 = undefined;
    var w = codec.Writer.init(&buf);
    try w.enumValue(proto.Version.tls_1_2);
    try w.slice(&handshake.hello_retry_request_random);
    try w.vector(u8, &session_id);
    try w.enumValue(proto.CipherSuite.aes_128_gcm_sha256);
    try w.byte(0);
    const ext = try w.beginLength(u16);
    try w.enumValue(proto.Extension.supported_versions);
    try w.vector(u16, &.{ 3, 4 });
    try w.enumValue(proto.Extension.key_share);
    try w.vector(u16, &.{ 0, 0x17 });
    try ext.end(&w);

    const hello = (try parseServerHello(w.written(), opt, &session_id)).tls13;
    try testing.expect(hello.is_retry);
    try testing.expectEqual(proto.NamedGroup.secp256r1, hello.key_share.?.group);
    try testing.expectEqual(null, hello.cookie);

    session_id[0] = 8;
    try testing.expectError(error.TlsIllegalParameter, parseServerHello(w.written(), opt, &session_id));
    session_id[0] = 7;
    // Drop supported_versions: a TLS 1.2 server.
    w = codec.Writer.init(&buf);
    try w.enumValue(proto.Version.tls_1_2);
    try w.slice(&handshake.hello_retry_request_random);
    try w.vector(u8, &session_id);
    try w.enumValue(proto.CipherSuite.aes_128_gcm_sha256);
    try w.byte(0);
    try w.vector(u16, &.{});
    try testing.expectError(error.TlsProtocolVersion, parseServerHello(w.written(), opt, &session_id));
}

/// A ServerHello body: `version` as legacy_version, the given random and
/// session ID, and `extensions` as the raw block (null for none at all).
fn testServerHello(buf: []u8, version: proto.Version, random: *const [32]u8, session_id: []const u8, suite: proto.CipherSuite, extensions: ?[]const u8) ![]const u8 {
    var w = codec.Writer.init(buf);
    try w.enumValue(version);
    try w.slice(random);
    try w.vector(u8, session_id);
    try w.enumValue(suite);
    try w.byte(0);
    if (extensions) |e| try w.vector(u16, e);
    return w.written();
}

test "a TLS 1.2 ServerHello, when TLS 1.2 is offered" {
    const both = proto.CipherSuite.all ++ proto.CipherSuite.tls12;
    const opt: config.Client = .{ .allocator = testing.allocator, .host = "localhost", .insecure_skip_verify = true, .now = undefined, .cipher_suites = &both };
    const only13: config.Client = .{ .allocator = testing.allocator, .host = "localhost", .insecure_skip_verify = true, .now = undefined };
    const ours: [32]u8 = @splat(7);
    const theirs: [32]u8 = @splat(9);
    var random: [32]u8 = @splat(0x5a);
    const suite: proto.CipherSuite = .ecdhe_ecdsa_with_aes_128_gcm_sha256;
    var buf: [256]u8 = undefined;

    // No extensions block at all, and one with what a server sends.
    var hello = (try parseServerHello(try testServerHello(&buf, .tls_1_2, &random, &theirs, suite, null), opt, &ours)).tls12;
    try testing.expectEqual(suite, hello.suite);
    try testing.expect(!hello.extended_master_secret);
    const usual = [_]u8{ 0xff, 0x01, 0, 1, 0 } ++ [_]u8{ 0, 23, 0, 0 } ++ [_]u8{ 0, 11, 0, 2, 1, 0 };
    hello = (try parseServerHello(try testServerHello(&buf, .tls_1_2, &random, "", suite, &usual), opt, &ours)).tls12;
    try testing.expect(hello.extended_master_secret);
    try testing.expectEqualSlices(u8, &random, &hello.random);

    // Not when we offered TLS 1.3 alone.
    try testing.expectError(error.TlsProtocolVersion, parseServerHello(try testServerHello(&buf, .tls_1_2, &random, &theirs, suite, null), only13, &ours));
    // The suite must be TLS 1.2's, and a TLS 1.2 suite needs TLS 1.2.
    try testing.expectError(error.TlsIllegalParameter, parseServerHello(try testServerHello(&buf, .tls_1_2, &random, &theirs, .aes_128_gcm_sha256, null), opt, &ours));
    const v13 = [_]u8{ 0, 43, 0, 2, 3, 4 };
    try testing.expectError(error.TlsIllegalParameter, parseServerHello(try testServerHello(&buf, .tls_1_2, &random, &ours, suite, &v13), opt, &ours));
    // supported_versions may not pick TLS 1.2.
    const v12 = [_]u8{ 0, 43, 0, 2, 3, 3 };
    try testing.expectError(error.TlsIllegalParameter, parseServerHello(try testServerHello(&buf, .tls_1_2, &random, &ours, suite, &v12), opt, &ours));
    // Anything older is refused, and TLS 1.3 only through supported_versions.
    try testing.expectError(error.TlsProtocolVersion, parseServerHello(try testServerHello(&buf, @enumFromInt(0x0302), &random, &theirs, suite, null), opt, &ours));
    try testing.expectError(error.TlsProtocolVersion, parseServerHello(try testServerHello(&buf, .tls_1_3, &random, &ours, .aes_128_gcm_sha256, null), opt, &ours));
    try testing.expectError(error.TlsProtocolVersion, parseServerHello(try testServerHello(&buf, .tls_1_3, &random, &ours, .aes_128_gcm_sha256, &.{}), only13, &ours));

    // The downgrade sentinels, since we offered TLS 1.3 too, but not when
    // we offered TLS 1.2 alone.
    const tls12_only: config.Client = .{ .allocator = testing.allocator, .host = "localhost", .insecure_skip_verify = true, .now = undefined, .cipher_suites = &proto.CipherSuite.tls12 };
    for ([_]*const [8]u8{ downgrade_tls12, downgrade_tls11 }) |sentinel| {
        random[24..].* = sentinel.*;
        try testing.expectError(error.TlsIllegalParameter, parseServerHello(try testServerHello(&buf, .tls_1_2, &random, &theirs, suite, null), opt, &ours));
        _ = try parseServerHello(try testServerHello(&buf, .tls_1_2, &random, &theirs, suite, null), tls12_only, "");
    }
    random = @splat(0x5a);
    // Our session ID back: resumption we never asked for.
    try testing.expectError(error.TlsIllegalParameter, parseServerHello(try testServerHello(&buf, .tls_1_2, &random, &ours, suite, null), opt, &ours));

    // renegotiation_info must be empty; point formats must allow
    // uncompressed; nothing we did not offer.
    const reneg = [_]u8{ 0xff, 0x01, 0, 2, 1, 0 };
    try testing.expectError(error.TlsHandshakeFailure, parseServerHello(try testServerHello(&buf, .tls_1_2, &random, &theirs, suite, &reneg), opt, &ours));
    const formats = [_]u8{ 0, 11, 0, 2, 1, 1 };
    try testing.expectError(error.TlsIllegalParameter, parseServerHello(try testServerHello(&buf, .tls_1_2, &random, &theirs, suite, &formats), opt, &ours));
    const ticket = [_]u8{ 0, 35, 0, 0 };
    try testing.expectError(error.TlsUnsupportedExtension, parseServerHello(try testServerHello(&buf, .tls_1_2, &random, &theirs, suite, &ticket), opt, &ours));
    const key_share = [_]u8{ 0, 51, 0, 2, 0, 0x1d };
    try testing.expectError(error.TlsUnsupportedExtension, parseServerHello(try testServerHello(&buf, .tls_1_2, &random, &theirs, suite, &key_share), opt, &ours));
    const twice = [_]u8{ 0, 23, 0, 0, 0, 23, 0, 0 };
    try testing.expectError(error.TlsDecodeError, parseServerHello(try testServerHello(&buf, .tls_1_2, &random, &theirs, suite, &twice), opt, &ours));
    // ALPN, as in TLS 1.3's EncryptedExtensions, but with none offered.
    const alpn = [_]u8{ 0, 16, 0, 5, 0, 3, 2, 'h', '2' };
    try testing.expectError(error.TlsUnsupportedExtension, parseServerHello(try testServerHello(&buf, .tls_1_2, &random, &theirs, suite, &alpn), opt, &ours));
}
