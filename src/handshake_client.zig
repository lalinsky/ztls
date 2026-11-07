//! The client's side of the handshake (RFC 8446 §2): ClientHello, a
//! HelloRetryRequest if the server wants another group, the server's
//! flight, then our Finished (and certificate, if asked).

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

pub fn run(conn: *Connection, options: config.Client) Error!void {
    var h = Handshake.init(conn, options.allocator, options.max_handshake_message_len);
    defer h.deinit();
    handshakeInner(&h, options) catch |err| {
        h.sendAlert(err);
        return err;
    };
}

/// What a ServerHello or HelloRetryRequest tells us.
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

fn handshakeInner(h: *Handshake, opt: config.Client) Error!void {
    // Misconfiguration is ours, not the peer's.
    if (opt.root_ca == null and !opt.insecure_skip_verify) return error.TlsInternalError;
    if (opt.cipher_suites.len == 0 or opt.named_groups.len == 0 or opt.key_shares.len == 0) return error.TlsInternalError;
    for (opt.key_shares) |group| {
        if (std.mem.indexOfScalar(proto.NamedGroup, opt.named_groups, group) == null) return error.TlsInternalError;
    }

    var random: [32]u8 = undefined;
    crypto.rand.bytes(&random);
    // A non-empty legacy_session_id asks the server for middlebox
    // compatibility mode (§D.4); both sides then send a dummy CCS.
    var session_id: [32]u8 = undefined;
    crypto.rand.bytes(&session_id);

    var shares = try KeyShares.generate(opt.key_shares);
    defer shares.deinit();
    try writeClientHello(h, opt, &random, &session_id, &shares, opt.key_shares, null);
    try h.flush();

    var msg = try h.nextMessage();
    try h.expect(msg, .server_hello);
    var hello = try parseServerHello(msg.body, opt, &session_id);
    var sent_ccs = false;
    if (hello.is_retry) {
        h.setSuite(hello.suite);
        h.transcript.replaceWithMessageHash();
        h.hashMessage(msg);
        // A retry must change something (§4.1.4): a group we support and
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
        try writeClientHello(h, opt, &random, &session_id, &shares, share_groups, hello.cookie);
        try h.flush();

        msg = try h.nextMessage();
        try h.expect(msg, .server_hello);
        const second = try parseServerHello(msg.body, opt, &session_id);
        if (second.is_retry) return error.TlsUnexpectedMessage;
        if (second.suite != hello.suite) return error.TlsIllegalParameter;
        hello = second;
    } else {
        h.setSuite(hello.suite);
    }
    h.hashMessage(msg);

    const key_share = hello.key_share orelse return error.TlsMissingExtension;
    if (!shares.has(key_share.group)) return error.TlsIllegalParameter;
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
    h.hashMessage(msg);

    msg = try h.nextMessage();
    var request: ?CertificateRequest = null;
    if (msg.handshake_type == .certificate_request) {
        request = try parseCertificateRequest(msg.body, opt.auth);
        h.hashMessage(msg);
        msg = try h.nextMessage();
    }

    try h.expect(msg, .certificate);
    // A server's chain is never empty (§4.4.2).
    var peer = (try h.parseCertificate(msg.body, "")) orelse return error.TlsDecodeError;
    defer peer.deinit();
    h.conn.peer_key_type = peer.public_key.key_type;
    if (!opt.insecure_skip_verify) {
        try h.verifyChain(&peer, opt.root_ca.?, .server, opt.host, opt.now.toSeconds());
    }
    h.hashMessage(msg);

    msg = try h.nextMessage();
    try h.expect(msg, .certificate_verify);
    try h.verifyCertificateVerify(msg.body, &peer.public_key, .server);
    h.hashMessage(msg);

    msg = try h.nextMessage();
    try h.expect(msg, .finished);
    try h.verifyFinished(msg.body, &hs.server);
    h.hashMessage(msg);

    var ap = h.deriveApplicationSecrets();
    defer ap.wipe();

    // Our flight.
    if (request) |req| {
        if (opt.auth != null and req.scheme != null) {
            try h.writeCertificate(req.context(), opt.auth.?);
            try h.writeCertificateVerify(opt.auth.?, req.scheme.?, .client);
        } else {
            // Nothing to show: an empty Certificate (§4.4.2).
            try h.writeCertificate(req.context(), null);
        }
    }
    try h.writeFinished(&hs.client);
    try h.flush();

    try h.installReadKeys(ap.server);
    try h.installWriteKeys(ap.client);
    h.conn.read.in_handshake = false;
    h.conn.alpn_protocol = alpn;
    h.conn.strict_close_notify = opt.strict_close_notify;
}

/// Whether `host` is an IP literal, which gets no SNI (RFC 6066 §3).
fn isIpLiteral(host: []const u8) bool {
    _ = std.Io.net.IpAddress.parse(host, 0) catch return false;
    return true;
}

fn writeClientHello(
    h: *Handshake,
    opt: config.Client,
    random: *const [32]u8,
    session_id: *const [32]u8,
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
    session_id: *const [32]u8,
    shares: *const KeyShares,
    share_groups: []const proto.NamedGroup,
    cookie: ?[]const u8,
) codec.Writer.Error!void {
    try w.enumValue(proto.HandshakeType.client_hello);
    const message = try w.beginLength(u24);
    try w.enumValue(proto.Version.tls_1_2);
    try w.slice(random);
    try w.vector(u8, session_id);
    try w.enumList(opt.cipher_suites);
    try w.vector(u8, &.{0}); // legacy_compression_methods: null only
    const extensions = try w.beginLength(u16);
    if (!isIpLiteral(opt.host)) {
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
        try w.enumList(opt.named_groups);
        try ext.end(w);
    }
    {
        try w.enumValue(proto.Extension.signature_algorithms);
        const ext = try w.beginLength(u16);
        try w.enumList(&handshake.signature_algorithms);
        try ext.end(w);
    }
    {
        try w.enumValue(proto.Extension.supported_versions);
        const ext = try w.beginLength(u16);
        try w.byte(2);
        try w.enumValue(proto.Version.tls_1_3);
        try ext.end(w);
    }
    if (opt.alpn_protocols.len > 0) {
        try w.enumValue(proto.Extension.application_layer_protocol_negotiation);
        const ext = try w.beginLength(u16);
        const list = try w.beginLength(u16);
        for (opt.alpn_protocols) |name| try w.vector(u8, name);
        try list.end(w);
        try ext.end(w);
    }
    {
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

fn parseServerHello(body: []const u8, opt: config.Client, session_id: *const [32]u8) Error!ServerHello {
    var d = codec.Decoder.init(body);
    if (try d.decode(proto.Version) != .tls_1_2) return error.TlsProtocolVersion;
    const random = try d.array(32);
    const is_retry = std.mem.eql(u8, random, &handshake.hello_retry_request_random);
    if (!std.mem.eql(u8, try d.vectorBytes(u8), session_id)) return error.TlsIllegalParameter;
    const suite = try d.decode(proto.CipherSuite);
    if (std.mem.indexOfScalar(proto.CipherSuite, opt.cipher_suites, suite) == null) return error.TlsIllegalParameter;
    if (try d.decode(u8) != 0) return error.TlsIllegalParameter; // compression
    var extensions = try d.vector(u16);
    try d.expectEof();

    var hello: ServerHello = .{ .is_retry = is_retry, .suite = suite, .key_share = null };
    var saw_versions = false;
    while (!extensions.eof()) {
        const extension = try extensions.decode(proto.Extension);
        var data = try extensions.vector(u16);
        switch (extension) {
            .supported_versions => {
                if (saw_versions) return error.TlsIllegalParameter;
                saw_versions = true;
                if (try data.decode(proto.Version) != .tls_1_3) return error.TlsIllegalParameter;
            },
            .key_share => {
                if (hello.key_share != null) return error.TlsIllegalParameter;
                const group = try data.decode(proto.NamedGroup);
                hello.key_share = .{ .group = group, .share = if (is_retry) &.{} else try data.vectorBytes(u16) };
            },
            .cookie => {
                if (!is_retry or hello.cookie != null) return error.TlsIllegalParameter;
                hello.cookie = try data.vectorBytes(u16);
            },
            // We offered no PSK, so nothing else belongs here (§4.1.3).
            else => return error.TlsUnsupportedExtension,
        }
        try data.expectEof();
    }
    // Without supported_versions this would be a TLS 1.2 ServerHello.
    if (!saw_versions) return error.TlsProtocolVersion;
    return hello;
}

/// Returns the ALPN protocol the server chose, as our own slice.
fn parseEncryptedExtensions(body: []const u8, opt: config.Client) Error!?[]const u8 {
    var d = codec.Decoder.init(body);
    var extensions = try d.vector(u16);
    try d.expectEof();
    var alpn: ?[]const u8 = null;
    while (!extensions.eof()) {
        const extension = try extensions.decode(proto.Extension);
        var data = try extensions.vector(u16);
        switch (extension) {
            .application_layer_protocol_negotiation => {
                if (opt.alpn_protocols.len == 0 or alpn != null) return error.TlsUnsupportedExtension;
                var list = try data.vector(u16);
                const name = try list.vectorBytes(u8);
                try list.expectEof();
                for (opt.alpn_protocols) |ours| {
                    if (std.mem.eql(u8, ours, name)) alpn = ours;
                }
                // Not something we offered.
                if (alpn == null) return error.TlsIllegalParameter;
            },
            // An acknowledgement of our SNI, and the server's preferences.
            .server_name, .supported_groups => {},
            else => return error.TlsUnsupportedExtension,
        }
        if (extension != .supported_groups) try data.expectEof();
    }
    return alpn;
}

fn parseCertificateRequest(body: []const u8, auth: ?*const config.CertKeyPair) Error!CertificateRequest {
    var d = codec.Decoder.init(body);
    const context = try d.vectorBytes(u8);
    var extensions = try d.vector(u16);
    try d.expectEof();

    var request: CertificateRequest = .{ .context_buf = undefined, .context_len = @intCast(context.len), .scheme = null };
    @memcpy(request.context_buf[0..context.len], context);

    var offered: [64]proto.SignatureScheme = undefined;
    var offered_len: ?usize = null;
    while (!extensions.eof()) {
        const extension = try extensions.decode(proto.Extension);
        var data = try extensions.vector(u16);
        switch (extension) {
            .signature_algorithms => {
                if (offered_len != null) return error.TlsIllegalParameter;
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
            // certificate_authorities, oid_filters and the rest only narrow
            // what the server would like; we offer what we have.
            else => {},
        }
    }
    const n = offered_len orelse return error.TlsMissingExtension;
    if (auth) |pair| request.scheme = handshake.selectScheme(pair.key.key_type, offered[0..n]);
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

    const hello = try parseServerHello(w.written(), opt, &session_id);
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
