//! ztls: TLS 1.3, and a TLS 1.2 client, on AWS-LC's libcrypto. See
//! DESIGN.md.
//!
//! `client` and `server` run a handshake over a transport's reader and
//! writer and return a `Connection`, whose `reader`, `writer` and
//! `writerInPlace` carry cleartext.

const std = @import("std");
const Io = std.Io;

pub const crypto = @import("crypto.zig");
pub const protocol = @import("protocol.zig");
pub const codec = @import("codec.zig");
pub const key_schedule = @import("key_schedule.zig");
pub const cipher = @import("cipher.zig");
pub const connection = @import("connection.zig");
pub const config = @import("config.zig");
pub const handshake = @import("handshake.zig");
const handshake_client = @import("handshake_client.zig");
const handshake_server = @import("handshake_server.zig");

/// For code written to tls.zig's API shape that adapts at comptime to
/// the few places this library differs, such as the allocator in the
/// options and the trust store type: check `@hasDecl(tls, "is_ztls")`.
pub const is_ztls = true;

pub const Connection = connection.Connection;
pub const TrustStore = config.TrustStore;
pub const CertKeyPair = config.CertKeyPair;
pub const Signer = config.Signer;
pub const Error = handshake.Error;

/// The transport reader's buffer must be at least this long: one whole
/// record.
pub const input_buffer_len = connection.input_buffer_len;
/// The transport writer's buffer must be at least this long: one whole
/// sealed record and the KeyUpdate that may go ahead of it.
pub const output_buffer_len = connection.output_buffer_len;

/// Runs the client side of a handshake over `input` and `output`, the
/// transport's ciphertext reader and writer. On failure the peer is told
/// why when that is something we found.
///
/// The Connection comes back by value; its readers and writers point at
/// it, so it must not move once they exist. The copy the handshake made
/// on its stack keeps the keys as residue; that is accepted, like the
/// shared secrets on the way to the key schedule.
pub fn client(input: *Io.Reader, output: *Io.Writer, options: config.Client) Error!Connection {
    var conn = Connection.init(input, output, .client);
    errdefer conn.deinit();
    try handshake_client.run(&conn, options);
    return conn;
}

/// Runs the server side of a handshake over `input` and `output`.
pub fn server(input: *Io.Reader, output: *Io.Writer, options: config.Server) Error!Connection {
    var conn = Connection.init(input, output, .server);
    errdefer conn.deinit();
    try handshake_server.run(&conn, options);
    return conn;
}

test {
    std.testing.refAllDecls(@This());
    _ = @import("interop_test.zig");
    _ = @import("handshake_client_tls12.zig");
}

const testing = std.testing;
const testu = @import("testu.zig");
const proto = protocol;

/// The test PKI, loaded.
const Pki = struct {
    ca: TrustStore,
    server_ec: CertKeyPair,
    server_rsa: CertKeyPair,
    server_ed25519: CertKeyPair,
    server_chain: CertKeyPair,
    client: CertKeyPair,
    selfsigned: CertKeyPair,

    fn init() !Pki {
        var ca = try TrustStore.init();
        errdefer ca.deinit();
        try ca.addPem(testing.allocator, @embedFile("testdata/pki/ca.pem"));
        return .{
            .ca = ca,
            .server_ec = try pair("server-ec"),
            .server_rsa = try pair("server-rsa"),
            .server_ed25519 = try pair("server-ed25519"),
            .server_chain = try pair("server-chain"),
            .client = try pair("client"),
            .selfsigned = try pair("selfsigned"),
        };
    }

    fn pair(comptime name: []const u8) !CertKeyPair {
        return CertKeyPair.fromSlice(testing.allocator, @embedFile("testdata/pki/" ++ name ++ ".pem"), @embedFile("testdata/pki/" ++ name ++ ".key"));
    }

    fn deinit(p: *Pki) void {
        p.ca.deinit();
        p.server_ec.deinit(testing.allocator);
        p.server_rsa.deinit(testing.allocator);
        p.server_ed25519.deinit(testing.allocator);
        p.server_chain.deinit(testing.allocator);
        p.client.deinit(testing.allocator);
        p.selfsigned.deinit(testing.allocator);
    }
};

/// Within the test PKI's validity (2027-01-15).
const valid_now: Io.Timestamp = .{ .nanoseconds = 1_800_000_000 * std.time.ns_per_s };

/// One end's transport: the socket with its buffers, pinned in place.
const Transport = struct {
    io: Io,
    stream: Io.net.Stream,
    input_buffer: [input_buffer_len]u8 = undefined,
    output_buffer: [output_buffer_len]u8 = undefined,
    input: Io.net.Stream.Reader = undefined,
    output: Io.net.Stream.Writer = undefined,

    fn setUp(t: *Transport) void {
        t.input = t.stream.reader(t.io, &t.input_buffer);
        t.output = t.stream.writer(t.io, &t.output_buffer);
    }

    fn deinit(t: *Transport) void {
        t.stream.close(t.io);
    }

    /// After refusing the peer: stop sending, read whatever it still
    /// sends until it hangs up, then close. Closing with unread input
    /// would reset the connection and could throw away the alert we just
    /// sent before the peer reads it.
    fn lingerClose(t: *Transport) void {
        t.stream.shutdown(t.io, .send) catch {};
        _ = t.input.interface.discardRemaining() catch {};
    }
};

/// What a self-talk server does once its handshake is done, and what it
/// reports back.
const ServerOutcome = struct {
    handshake: Error!void = {},
    alpn: ?[]const u8 = null,
    /// The echo loop's failure, if any.
    echo: anyerror!void = {},
};

/// The server end of a self-talk test: accept, handshake, echo lines
/// until the client is done, close.
fn serveOnce(loopback: *testu.Loopback, options: config.Server, outcome: *ServerOutcome) anyerror!void {
    var t: Transport = .{ .io = loopback.io, .stream = try loopback.accept() };
    defer t.deinit();
    t.setUp();
    var conn = server(&t.input.interface, &t.output.interface, options) catch |err| {
        outcome.handshake = err;
        t.lingerClose();
        return;
    };
    defer conn.deinit();
    outcome.alpn = conn.alpn_protocol;
    outcome.echo = echo(&conn);
}

fn echo(conn: *Connection) !void {
    var rbuf: [1024]u8 = undefined;
    var r = conn.reader(&rbuf);
    var w = conn.writerInPlace();
    while (r.interface.takeDelimiter('\n') catch |err| return r.err orelse err) |line| {
        try w.interface.print("echo: {s}\n", .{line});
        try w.interface.flush();
    }
    try conn.close();
}

/// Connects, handshakes and exchanges a few lines.
fn clientOnce(loopback: *const testu.Loopback, options: config.Client) !Connection {
    var t: Transport = .{ .io = loopback.io, .stream = try loopback.connect() };
    defer t.deinit();
    t.setUp();
    var conn = client(&t.input.interface, &t.output.interface, options) catch |err| {
        t.lingerClose();
        return err;
    };
    defer conn.deinit();
    var rbuf: [1024]u8 = undefined;
    var r = conn.reader(&rbuf);
    var w = conn.writerInPlace();
    for (0..3) |i| {
        try w.interface.print("hello {d}\n", .{i});
        try w.interface.flush();
        // A server that rejects our certificate does so after our
        // handshake is over; its alert arrives with the first read.
        const line = r.interface.takeDelimiter('\n') catch |err| return r.err orelse err;
        var expected: [32]u8 = undefined;
        try testing.expectEqualStrings(try std.fmt.bufPrint(&expected, "echo: hello {d}", .{i}), line.?);
    }
    try conn.close();
    try testing.expectEqual(null, try r.interface.takeDelimiter('\n'));
    return conn;
}

const Run = struct {
    loopback: testu.Loopback,
    outcome: ServerOutcome = .{},
    task: Io.Future(anyerror!void) = undefined,

    fn start(r: *Run, io: Io, options: config.Server) !void {
        r.loopback = try testu.Loopback.init(io);
        errdefer r.loopback.deinit();
        r.task = try io.concurrent(serveOnce, .{ &r.loopback, options, &r.outcome });
    }

    fn finish(r: *Run, io: Io) !ServerOutcome {
        defer r.loopback.deinit();
        try r.task.await(io);
        return r.outcome;
    }
};

test "client and server handshake with every suite, group and certificate type" {
    const io = testing.io;
    var pki = try Pki.init();
    defer pki.deinit();

    const groups = [_]proto.NamedGroup{ .x25519_ml_kem768, .x25519, .secp256r1, .secp384r1 };
    const pairs = [_]*const CertKeyPair{ &pki.server_ec, &pki.server_rsa, &pki.server_ed25519, &pki.server_chain };
    for (proto.CipherSuite.all) |suite| {
        for (groups) |group| {
            for (pairs) |pair| {
                var run: Run = .{ .loopback = undefined };
                try run.start(io, .{ .allocator = testing.allocator, .auth = pair, .now = valid_now, .alpn_protocols = &.{ "h2", "http/1.1" } });
                const conn = try clientOnce(&run.loopback, .{
                    .allocator = testing.allocator,
                    .host = "localhost",
                    .root_ca = &pki.ca,
                    .now = valid_now,
                    .cipher_suites = &.{suite},
                    .named_groups = &.{group},
                    .key_shares = &.{group},
                    .alpn_protocols = &.{ "http/1.1", "h2" },
                });
                try testing.expectEqualStrings("h2", conn.alpn_protocol.?);
                const outcome = try run.finish(io);
                try outcome.handshake;
                try outcome.echo;
                try testing.expectEqualStrings("h2", outcome.alpn.?);
            }
        }
    }
}

test "a default server takes ChaCha20-Poly1305 from a client that lists it first" {
    const io = testing.io;
    var pki = try Pki.init();
    defer pki.deinit();
    const aes_hardware = crypto.aead.hasAesHardware();
    for ([_][]const proto.CipherSuite{
        &.{ .chacha20_poly1305_sha256, .aes_128_gcm_sha256 },
        &.{ .aes_128_gcm_sha256, .chacha20_poly1305_sha256 },
    }) |offered| {
        var run: Run = .{ .loopback = undefined };
        try run.start(io, .{ .allocator = testing.allocator, .auth = &pki.server_ec, .now = valid_now });
        const conn = try clientOnce(&run.loopback, .{
            .allocator = testing.allocator,
            .host = "localhost",
            .root_ca = &pki.ca,
            .now = valid_now,
            .cipher_suites = offered,
        });
        const outcome = try run.finish(io);
        try outcome.handshake;
        // AES-GCM first only when both sides have AES instructions.
        const expected: proto.CipherSuite = if (offered[0] == .aes_128_gcm_sha256 and aes_hardware) .aes_128_gcm_sha256 else .chacha20_poly1305_sha256;
        try testing.expectEqual(expected, conn.suite.?);
    }
}

test "a HelloRetryRequest when the client sent no share the server takes" {
    const io = testing.io;
    var pki = try Pki.init();
    defer pki.deinit();
    var run: Run = .{ .loopback = undefined };
    try run.start(io, .{ .allocator = testing.allocator, .auth = &pki.server_ec, .now = valid_now, .named_groups = &.{.secp256r1} });
    _ = try clientOnce(&run.loopback, .{
        .allocator = testing.allocator,
        .host = "localhost",
        .root_ca = &pki.ca,
        .now = valid_now,
        .named_groups = &.{ .x25519, .secp256r1 },
        .key_shares = &.{.x25519},
    });
    const outcome = try run.finish(io);
    try outcome.handshake;
    try outcome.echo;
}

test "client certificates: none, requested, required" {
    const io = testing.io;
    var pki = try Pki.init();
    defer pki.deinit();

    const Case = struct { auth_type: config.ClientAuth.Type, client_pair: ?*const CertKeyPair, client_err: ?anyerror, server_err: ?anyerror };
    const cases = [_]Case{
        .{ .auth_type = .request, .client_pair = &pki.client, .client_err = null, .server_err = null },
        .{ .auth_type = .request, .client_pair = null, .client_err = null, .server_err = null },
        .{ .auth_type = .require, .client_pair = &pki.client, .client_err = null, .server_err = null },
        .{ .auth_type = .require, .client_pair = null, .client_err = error.TlsAlertCertificateRequired, .server_err = error.TlsCertificateRequired },
        .{ .auth_type = .require, .client_pair = &pki.selfsigned, .client_err = error.TlsAlertUnknownCa, .server_err = error.CertificateIssuerNotFound },
    };
    for (cases) |case| {
        var run: Run = .{ .loopback = undefined };
        try run.start(io, .{
            .allocator = testing.allocator,
            .auth = &pki.server_ec,
            .now = valid_now,
            .client_auth = .{ .root_ca = &pki.ca, .auth_type = case.auth_type },
        });
        const result = clientOnce(&run.loopback, .{
            .allocator = testing.allocator,
            .host = "localhost",
            .root_ca = &pki.ca,
            .now = valid_now,
            .auth = case.client_pair,
        });
        const outcome = try run.finish(io);
        if (case.client_err) |expected| {
            try testing.expectError(expected, result);
            try testing.expectError(case.server_err.?, outcome.handshake);
        } else {
            _ = try result;
            try outcome.handshake;
            try outcome.echo;
        }
    }
}

test "a signer hook signs CertificateVerify, once per side that presents a certificate" {
    const io = testing.io;
    var pki = try Pki.init();
    defer pki.deinit();

    // Signs on another task, as a thread pool would, while the handshake
    // waits.
    const Counting = struct {
        io: Io,
        calls: usize = 0,

        fn sign(context: ?*anyopaque, key: *const config.PrivateKey, algorithm: crypto.sig.Algorithm, message: []const u8, out: []u8) anyerror![]u8 {
            const self: *@This() = @ptrCast(@alignCast(context.?));
            self.calls += 1;
            var job = try self.io.concurrent(config.PrivateKey.sign, .{ key, algorithm, message, out });
            return job.await(self.io);
        }
    };
    var server_signer: Counting = .{ .io = io };
    var client_signer: Counting = .{ .io = io };
    // Copies share the chain and key with the originals, which own them.
    var server_pair = pki.server_rsa;
    server_pair.signer = .{ .context = &server_signer, .sign = Counting.sign };
    var client_pair = pki.client;
    client_pair.signer = .{ .context = &client_signer, .sign = Counting.sign };

    // Mutual authentication: each side signs once, through its hook.
    var run: Run = .{ .loopback = undefined };
    try run.start(io, .{
        .allocator = testing.allocator,
        .auth = &server_pair,
        .now = valid_now,
        .client_auth = .{ .root_ca = &pki.ca, .auth_type = .require },
    });
    _ = try clientOnce(&run.loopback, .{ .allocator = testing.allocator, .host = "localhost", .root_ca = &pki.ca, .now = valid_now, .auth = &client_pair });
    var outcome = try run.finish(io);
    try outcome.handshake;
    try outcome.echo;
    try testing.expectEqual(1, server_signer.calls);
    try testing.expectEqual(1, client_signer.calls);

    // No client certificate asked for: the client's hook stays unused.
    run = .{ .loopback = undefined };
    try run.start(io, .{ .allocator = testing.allocator, .auth = &server_pair, .now = valid_now });
    _ = try clientOnce(&run.loopback, .{ .allocator = testing.allocator, .host = "localhost", .root_ca = &pki.ca, .now = valid_now, .auth = &client_pair });
    outcome = try run.finish(io);
    try outcome.handshake;
    try outcome.echo;
    try testing.expectEqual(2, server_signer.calls);
    try testing.expectEqual(1, client_signer.calls);

    // A hook that fails ends the handshake as our own error.
    const Failing = struct {
        fn sign(_: ?*anyopaque, _: *const config.PrivateKey, _: crypto.sig.Algorithm, _: []const u8, _: []u8) anyerror![]u8 {
            return error.KeyUnavailable;
        }
    };
    server_pair.signer = .{ .sign = Failing.sign };
    run = .{ .loopback = undefined };
    try run.start(io, .{ .allocator = testing.allocator, .auth = &server_pair, .now = valid_now });
    try testing.expectError(error.TlsAlertInternalError, clientOnce(&run.loopback, .{ .allocator = testing.allocator, .host = "localhost", .root_ca = &pki.ca, .now = valid_now }));
    outcome = try run.finish(io);
    try testing.expectError(error.TlsInternalError, outcome.handshake);
}

test "the client refuses a certificate it cannot trust, and tells the server" {
    const io = testing.io;
    var pki = try Pki.init();
    defer pki.deinit();

    const Case = struct { server_pair: *const CertKeyPair, host: []const u8, now: Io.Timestamp, skip_verify: bool = false, client_err: ?anyerror, server_err: ?anyerror };
    const cases = [_]Case{
        .{ .server_pair = &pki.selfsigned, .host = "localhost", .now = valid_now, .client_err = error.CertificateIssuerNotFound, .server_err = error.TlsAlertUnknownCa },
        .{ .server_pair = &pki.server_ec, .host = "example.org", .now = valid_now, .client_err = error.CertificateHostMismatch, .server_err = error.TlsAlertBadCertificate },
        .{ .server_pair = &pki.server_ec, .host = "localhost", .now = .{ .nanoseconds = 1_000_000_000 * std.time.ns_per_s }, .client_err = error.CertificateNotYetValid, .server_err = error.TlsAlertCertificateExpired },
        .{ .server_pair = &pki.selfsigned, .host = "localhost", .now = valid_now, .skip_verify = true, .client_err = null, .server_err = null },
        .{ .server_pair = &pki.server_ec, .host = "127.0.0.1", .now = valid_now, .client_err = null, .server_err = null },
        .{ .server_pair = &pki.server_ec, .host = "10.0.0.1", .now = valid_now, .client_err = error.CertificateHostMismatch, .server_err = error.TlsAlertBadCertificate },
    };
    for (cases) |case| {
        var run: Run = .{ .loopback = undefined };
        try run.start(io, .{ .allocator = testing.allocator, .auth = case.server_pair, .now = valid_now });
        const result = clientOnce(&run.loopback, .{
            .allocator = testing.allocator,
            .host = case.host,
            .root_ca = &pki.ca,
            .insecure_skip_verify = case.skip_verify,
            .now = case.now,
        });
        const outcome = try run.finish(io);
        if (case.client_err) |expected| {
            try testing.expectError(expected, result);
            try testing.expectError(case.server_err.?, outcome.handshake);
        } else {
            _ = try result;
            try outcome.handshake;
            try outcome.echo;
        }
    }
}

test "no common ALPN protocol, suite or group ends the handshake" {
    const io = testing.io;
    var pki = try Pki.init();
    defer pki.deinit();

    const Case = struct { server: config.Server, client: config.Client, client_err: anyerror, server_err: anyerror };
    const base_server: config.Server = .{ .allocator = testing.allocator, .auth = &pki.server_ec, .now = valid_now };
    const base_client: config.Client = .{ .allocator = testing.allocator, .host = "localhost", .root_ca = &pki.ca, .now = valid_now };
    var alpn_server = base_server;
    alpn_server.alpn_protocols = &.{"h2"};
    var alpn_client = base_client;
    alpn_client.alpn_protocols = &.{"http/1.1"};
    var suite_server = base_server;
    suite_server.cipher_suites = &.{.aes_256_gcm_sha384};
    var suite_client = base_client;
    suite_client.cipher_suites = &.{.chacha20_poly1305_sha256};
    var group_server = base_server;
    group_server.named_groups = &.{.secp384r1};
    var group_client = base_client;
    group_client.named_groups = &.{.x25519};
    group_client.key_shares = &.{.x25519};
    const cases = [_]Case{
        .{ .server = alpn_server, .client = alpn_client, .client_err = error.TlsAlertNoApplicationProtocol, .server_err = error.TlsNoApplicationProtocol },
        .{ .server = suite_server, .client = suite_client, .client_err = error.TlsAlertHandshakeFailure, .server_err = error.TlsHandshakeFailure },
        .{ .server = group_server, .client = group_client, .client_err = error.TlsAlertHandshakeFailure, .server_err = error.TlsHandshakeFailure },
    };
    for (cases) |case| {
        var run: Run = .{ .loopback = undefined };
        try run.start(io, case.server);
        try testing.expectError(case.client_err, clientOnce(&run.loopback, case.client));
        const outcome = try run.finish(io);
        try testing.expectError(case.server_err, outcome.handshake);
    }
}

test "signature scheme lists decide what each side signs with and accepts" {
    const io = testing.io;
    var pki = try Pki.init();
    defer pki.deinit();

    const Case = struct {
        server_signing: []const proto.SignatureScheme = &config.default_signature_schemes,
        client_verify: []const proto.SignatureScheme = &config.default_signature_schemes,
        expected: ?proto.SignatureScheme,
    };
    const cases = [_]Case{
        // The server's order wins among what the client takes.
        .{ .server_signing = &.{ .rsa_pss_rsae_sha512, .rsa_pss_rsae_sha256 }, .expected = .rsa_pss_rsae_sha512 },
        .{ .client_verify = &.{ .ecdsa_secp256r1_sha256, .rsa_pss_rsae_sha384 }, .expected = .rsa_pss_rsae_sha384 },
        // Nothing in common for an RSA key.
        .{ .client_verify = &.{.ecdsa_secp256r1_sha256}, .expected = null },
        .{ .server_signing = &.{.ed25519}, .expected = null },
    };
    for (cases) |case| {
        var run: Run = .{ .loopback = undefined };
        try run.start(io, .{ .allocator = testing.allocator, .auth = &pki.server_rsa, .now = valid_now, .signing_schemes = case.server_signing });
        const result = clientOnce(&run.loopback, .{
            .allocator = testing.allocator,
            .host = "localhost",
            .root_ca = &pki.ca,
            .now = valid_now,
            .verify_schemes = case.client_verify,
        });
        const outcome = try run.finish(io);
        if (case.expected) |scheme| {
            const conn = try result;
            try testing.expectEqual(scheme, conn.peer_signature_scheme.?);
            try outcome.handshake;
        } else {
            try testing.expectError(error.TlsAlertHandshakeFailure, result);
            try testing.expectError(error.TlsHandshakeFailure, outcome.handshake);
        }
    }

    // A client certificate the server would not take is left out.
    var run: Run = .{ .loopback = undefined };
    try run.start(io, .{
        .allocator = testing.allocator,
        .auth = &pki.server_ec,
        .now = valid_now,
        .client_auth = .{ .root_ca = &pki.ca, .auth_type = .require },
        .verify_schemes = &.{.ed25519},
    });
    try testing.expectError(error.TlsAlertCertificateRequired, clientOnce(&run.loopback, .{
        .allocator = testing.allocator,
        .host = "localhost",
        .root_ca = &pki.ca,
        .now = valid_now,
        .auth = &pki.client,
    }));
    const outcome = try run.finish(io);
    try testing.expectError(error.TlsCertificateRequired, outcome.handshake);
}

test "signature scheme lists must be ones we implement, each once" {
    var input_buffer: [input_buffer_len]u8 = undefined;
    var output_buffer: [output_buffer_len]u8 = undefined;
    const bad = [_][]const proto.SignatureScheme{
        &.{},
        &.{.rsa_pkcs1_sha1},
        &.{ .ed25519, .ed25519 },
    };
    for (bad, 0..) |schemes, i| {
        // An empty list is fine only for a client's signing.
        const Side = enum { client_verify, client_signing, server_verify, server_signing };
        for (std.enums.values(Side)) |side| {
            if (i == 0 and side == .client_signing) continue;
            var input: Io.Reader = .fixed(&input_buffer);
            var discard: Io.Writer.Discarding = .init(&output_buffer);
            const result = switch (side) {
                .client_verify, .client_signing => client(&input, &discard.writer, .{
                    .allocator = testing.allocator,
                    .host = "localhost",
                    .insecure_skip_verify = true,
                    .now = valid_now,
                    .verify_schemes = if (side == .client_verify) schemes else &config.default_signature_schemes,
                    .signing_schemes = if (side == .client_signing) schemes else &config.default_signature_schemes,
                }),
                .server_verify, .server_signing => server(&input, &discard.writer, .{
                    .allocator = testing.allocator,
                    .auth = null,
                    .now = valid_now,
                    .verify_schemes = if (side == .server_verify) schemes else &config.default_signature_schemes,
                    .signing_schemes = if (side == .server_signing) schemes else &config.default_signature_schemes,
                }),
            };
            try testing.expectError(error.TlsInternalError, result);
            try testing.expectEqual(0, discard.count + discard.writer.end);
        }
    }
}

test "the server picks its certificate by server name" {
    const io = testing.io;
    var pki = try Pki.init();
    defer pki.deinit();

    // The application's own choice: the RSA pair for one name only.
    const Picker = struct {
        rsa: *const CertKeyPair,
        calls: usize = 0,

        fn pick(context: ?*anyopaque, hello: config.SelectCertificate.Hello) ?*const CertKeyPair {
            const self: *@This() = @ptrCast(@alignCast(context.?));
            self.calls += 1;
            const name = hello.server_name orelse return null;
            if (std.mem.eql(u8, name, "rsa.example.test") and hello.acceptsKey(self.rsa.key.key_type)) return self.rsa;
            return null;
        }
    };
    var picker: Picker = .{ .rsa = &pki.server_rsa };

    // Every test certificate is for localhost and *.example.test, so the
    // key type tells them apart.
    const Case = struct { host: []const u8, key_type: crypto.sig.KeyType, skip_verify: bool = false };
    const cases = [_]Case{
        .{ .host = "rsa.example.test", .key_type = .{ .rsa = 2048 } }, // the callback
        .{ .host = "www.example.test", .key_type = .{ .ecdsa = .p384 } }, // first of `certificates` for the name
        .{ .host = "nomatch.invalid", .key_type = .ed25519, .skip_verify = true }, // nothing fits: `auth`
    };
    for (cases) |case| {
        var run: Run = .{ .loopback = undefined };
        try run.start(io, .{
            .allocator = testing.allocator,
            .auth = &pki.server_ed25519,
            .certificates = &.{ &pki.server_chain, &pki.server_ec },
            .select_certificate = .{ .context = &picker, .callback = Picker.pick },
            .now = valid_now,
        });
        var t: Transport = .{ .io = io, .stream = try run.loopback.connect() };
        defer t.deinit();
        t.setUp();
        var conn = try client(&t.input.interface, &t.output.interface, .{
            .allocator = testing.allocator,
            .host = case.host,
            .root_ca = &pki.ca,
            .insecure_skip_verify = case.skip_verify,
            .now = valid_now,
        });
        defer conn.deinit();
        try testing.expectEqual(case.key_type, conn.peer_key_type.?);
        try conn.close();
        const outcome = try run.finish(io);
        try outcome.handshake;
    }
    try testing.expectEqual(cases.len, picker.calls);

    // With no fallback, an unknown name is refused.
    var run: Run = .{ .loopback = undefined };
    try run.start(io, .{ .allocator = testing.allocator, .auth = null, .certificates = &.{&pki.server_ec}, .now = valid_now });
    try testing.expectError(error.TlsAlertUnrecognizedName, clientOnce(&run.loopback, .{
        .allocator = testing.allocator,
        .host = "nomatch.invalid",
        .root_ca = &pki.ca,
        .now = valid_now,
    }));
    const outcome = try run.finish(io);
    try testing.expectError(error.TlsUnrecognizedName, outcome.handshake);
}

test "an empty host is a misconfiguration unless verification is off" {
    var pki = try Pki.init();
    defer pki.deinit();
    // Refused before anything is read or written.
    var input_buffer: [input_buffer_len]u8 = undefined;
    var output_buffer: [output_buffer_len]u8 = undefined;
    var input: Io.Reader = .fixed(&input_buffer);
    var discard: Io.Writer.Discarding = .init(&output_buffer);
    try testing.expectError(error.TlsInternalError, client(&input, &discard.writer, .{
        .allocator = testing.allocator,
        .host = "",
        .root_ca = &pki.ca,
        .now = valid_now,
    }));
    try testing.expectEqual(0, discard.count + discard.writer.end);
}

const data13 = @import("testdata/tls13.zig");

test "change_cipher_spec before the ClientHello or between its fragments is refused" {
    const io = testing.io;
    var pki = try Pki.init();
    defer pki.deinit();
    const ccs = [_]u8{ @intFromEnum(proto.ContentType.change_cipher_spec), 3, 3, 0, 1, 1 };
    const hello = data13.client_hello;
    // The same ClientHello in two records with the CCS between them.
    const head = 100;
    const rest = hello.len - 5 - head;
    const split = [_]u8{ @intFromEnum(proto.ContentType.handshake), 3, 1, head >> 8, head & 0xff } ++ hello[5 .. 5 + head].* ++ ccs ++
        [_]u8{ @intFromEnum(proto.ContentType.handshake), 3, 3, rest >> 8, rest & 0xff } ++ hello[5 + head ..].*;
    const cases = [_][]const u8{ &(ccs ++ hello), &split };
    for (cases) |bytes| {
        var run: Run = .{ .loopback = undefined };
        try run.start(io, .{ .allocator = testing.allocator, .auth = &pki.server_ec, .now = valid_now });
        {
            var t: Transport = .{ .io = io, .stream = try run.loopback.connect() };
            defer t.deinit();
            t.setUp();
            try t.output.interface.writeAll(bytes);
            try t.output.interface.flush();
            t.lingerClose();
        }
        const outcome = try run.finish(io);
        try testing.expectError(error.TlsUnexpectedMessage, outcome.handshake);
    }
}

test "a peer that hangs up during the handshake" {
    const io = testing.io;
    var pki = try Pki.init();
    defer pki.deinit();
    var loopback = try testu.Loopback.init(io);
    defer loopback.deinit();

    const Rude = struct {
        fn run(l: *testu.Loopback) !void {
            const stream = try l.accept();
            defer stream.close(l.io);
            // Take the ClientHello first. Closing with it unread would
            // reset the connection instead of ending it, and what the
            // client then sees depends on the OS.
            var buf: [4096]u8 = undefined;
            var reader = stream.reader(l.io, &buf);
            const header = try reader.interface.takeArray(5);
            try reader.interface.discardAll(std.mem.readInt(u16, header[3..5], .big));
        }
    };
    var rude = try io.concurrent(Rude.run, .{&loopback});
    defer rude.cancel(io) catch {};
    var t: Transport = .{ .io = io, .stream = try loopback.connect() };
    defer t.deinit();
    t.setUp();
    try testing.expectError(error.EndOfStream, client(&t.input.interface, &t.output.interface, .{ .allocator = testing.allocator, .host = "localhost", .root_ca = &pki.ca, .now = valid_now }));
    try rude.await(io);
}
