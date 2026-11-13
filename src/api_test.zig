//! Tests of the public API, run against the implementation being built
//! (`-Dimpl`): what the native and the libssl implementation must both
//! do. Where they differ on purpose, the test says so.

const std = @import("std");
const Io = std.Io;
const testing = std.testing;
const build_options = @import("build_options");

const native = @import("root_native.zig");
const libssl_build = build_options.libssl;
/// The implementation under test.
const lib = if (libssl_build) @import("root_libssl.zig") else native;

const config = lib.config;
const crypto = lib.crypto;
const proto = lib.protocol;
const CertKeyPair = lib.CertKeyPair;
const TrustStore = lib.TrustStore;
const testu = @import("testu.zig");
const api = @import("api.zig");

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
    input_buffer: [lib.input_buffer_len]u8 = undefined,
    output_buffer: [lib.output_buffer_len]u8 = undefined,
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

    /// Sends `bytes` as they are, under the TLS connection.
    fn sendRaw(t: *Transport, bytes: []const u8) !void {
        try t.output.interface.writeAll(bytes);
        try t.output.interface.flush();
    }
};

/// What a self-talk server does once its handshake is done, and what it
/// reports back.
const ServerOutcome = struct {
    handshake: anyerror!void = {},
    alpn: ?[]const u8 = null,
    server_name_buf: [255]u8 = undefined,
    server_name: ?[]const u8 = null,
    /// The echo loop's failure, if any.
    echo: anyerror!void = {},
};

/// The server end of a self-talk test: accept, handshake, echo lines
/// until the client is done, close.
fn serveOnce(comptime L: type, loopback: *testu.Loopback, options: config.Server, outcome: *ServerOutcome) anyerror!void {
    var t: Transport = .{ .io = loopback.io, .stream = try loopback.accept() };
    defer t.deinit();
    t.setUp();
    var conn = L.server(&t.input.interface, &t.output.interface, options) catch |err| {
        outcome.handshake = err;
        t.lingerClose();
        return;
    };
    defer conn.deinit();
    outcome.alpn = conn.alpn_protocol;
    if (conn.serverName()) |name| {
        @memcpy(outcome.server_name_buf[0..name.len], name);
        outcome.server_name = outcome.server_name_buf[0..name.len];
    }
    outcome.echo = echo(&conn);
}

/// Echoes lines; through `writerInPlace` where the implementation has
/// one, so the clients' buffered writer and it are both exercised.
fn echo(conn: anytype) !void {
    var rbuf: [1024]u8 = undefined;
    var wbuf: [1024]u8 = undefined;
    var r = conn.reader(&rbuf);
    var w = if (@hasDecl(@TypeOf(conn.*), "writerInPlace")) conn.writerInPlace() else conn.writer(&wbuf);
    while (r.interface.takeDelimiter('\n') catch |err| return r.err orelse err) |line| {
        try w.interface.print("echo: {s}\n", .{line});
        try w.interface.flush();
    }
    try w.close();
}

/// What the client saw of a connection, kept past its end.
const ClientOutcome = struct {
    version: ?proto.Version,
    suite: ?proto.CipherSuite,
    group: ?proto.NamedGroup,
    retried: bool,
    alpn: ?[]const u8,
    peer_key_type: ?crypto.sig.KeyType,
    peer_signature_scheme: ?proto.SignatureScheme,
    peer_certificates: usize,
};

/// Connects, handshakes and exchanges a few lines.
fn clientOnce(comptime L: type, loopback: *const testu.Loopback, options: config.Client) !ClientOutcome {
    var t: Transport = .{ .io = loopback.io, .stream = try loopback.connect() };
    defer t.deinit();
    t.setUp();
    var conn = L.client(&t.input.interface, &t.output.interface, options) catch |err| {
        t.lingerClose();
        return err;
    };
    defer conn.deinit();
    var rbuf: [1024]u8 = undefined;
    var wbuf: [1024]u8 = undefined;
    var r = conn.reader(&rbuf);
    var w = conn.writer(&wbuf);
    for (0..3) |i| {
        try w.interface.print("hello {d}\n", .{i});
        w.interface.flush() catch return w.err.?;
        // A server that rejects our certificate does so after our
        // handshake is over; its alert arrives with the first read.
        const line = r.interface.takeDelimiter('\n') catch |err| return r.err orelse err;
        var expected: [32]u8 = undefined;
        try testing.expectEqualStrings(try std.fmt.bufPrint(&expected, "echo: hello {d}", .{i}), line.?);
    }
    try w.close();
    try testing.expectEqual(null, try r.interface.takeDelimiter('\n'));
    return .{
        .version = conn.version,
        .suite = conn.suite,
        .group = conn.group,
        .retried = conn.retried,
        .alpn = conn.alpn_protocol,
        .peer_key_type = conn.peer_key_type,
        .peer_signature_scheme = conn.peer_signature_scheme,
        .peer_certificates = conn.peer_certificates.len,
    };
}

/// A self-talk server on its own task, run by implementation `L`.
fn Run(comptime L: type) type {
    return struct {
        loopback: testu.Loopback = undefined,
        outcome: ServerOutcome = .{},
        task: Io.Future(anyerror!void) = undefined,

        const Self = @This();

        fn start(r: *Self, io: Io, options: config.Server) !void {
            r.loopback = try testu.Loopback.init(io);
            errdefer r.loopback.deinit();
            r.task = try io.concurrent(serve, .{ &r.loopback, options, &r.outcome });
        }

        fn serve(loopback: *testu.Loopback, options: config.Server, outcome: *ServerOutcome) anyerror!void {
            return serveOnce(L, loopback, options, outcome);
        }

        fn finish(r: *Self, io: Io) !*ServerOutcome {
            defer r.loopback.deinit();
            try r.task.await(io);
            return &r.outcome;
        }
    };
}

test "client and server handshake with every suite, group and certificate type" {
    const io = testing.io;
    var pki = try Pki.init();
    defer pki.deinit();

    const groups = [_]proto.NamedGroup{ .x25519_ml_kem768, .x25519, .secp256r1, .secp384r1 };
    const pairs = [_]*const CertKeyPair{ &pki.server_ec, &pki.server_rsa, &pki.server_ed25519, &pki.server_chain };
    for (proto.CipherSuite.all) |suite| {
        for (groups) |group| {
            for (pairs) |pair| {
                var run: Run(lib) = .{};
                try run.start(io, .{ .gpa = testing.allocator, .auth = pair, .now = valid_now, .alpn_protocols = &.{ "h2", "http/1.1" } });
                const seen = try clientOnce(lib, &run.loopback, .{
                    .gpa = testing.allocator,
                    .host = "localhost",
                    .root_ca = &pki.ca,
                    .now = valid_now,
                    .cipher_suites = &.{suite},
                    .named_groups = &.{group},
                    .key_shares = &.{group},
                    .alpn_protocols = &.{ "http/1.1", "h2" },
                    .keep_peer_certificates = true,
                });
                const outcome = try run.finish(io);
                try outcome.handshake;
                try outcome.echo;
                try testing.expectEqualStrings("h2", seen.alpn.?);
                try testing.expectEqualStrings("h2", outcome.alpn.?);
                try testing.expectEqualStrings("localhost", outcome.server_name.?);
                try testing.expectEqual(proto.Version.tls_1_3, seen.version.?);
                try testing.expectEqual(suite, seen.suite.?);
                try testing.expectEqual(group, seen.group.?);
                try testing.expectEqual(pair.key.key_type, seen.peer_key_type.?);
                try testing.expect(seen.peer_signature_scheme != null);
                try testing.expectEqual(pair.chain.len, seen.peer_certificates);
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
        var run: Run(lib) = .{};
        try run.start(io, .{ .gpa = testing.allocator, .auth = &pki.server_ec, .now = valid_now });
        const seen = try clientOnce(lib, &run.loopback, .{
            .gpa = testing.allocator,
            .host = "localhost",
            .root_ca = &pki.ca,
            .now = valid_now,
            .cipher_suites = offered,
        });
        const outcome = try run.finish(io);
        try outcome.handshake;
        // AES-GCM first only when both sides have AES instructions.
        const expected: proto.CipherSuite = if (offered[0] == .aes_128_gcm_sha256 and aes_hardware) .aes_128_gcm_sha256 else .chacha20_poly1305_sha256;
        try testing.expectEqual(expected, seen.suite.?);
    }
}

test "a HelloRetryRequest when the client sent no share the server takes" {
    const io = testing.io;
    var pki = try Pki.init();
    defer pki.deinit();
    var run: Run(lib) = .{};
    try run.start(io, .{ .gpa = testing.allocator, .auth = &pki.server_ec, .now = valid_now, .named_groups = &.{.secp256r1} });
    const seen = try clientOnce(lib, &run.loopback, .{
        .gpa = testing.allocator,
        .host = "localhost",
        .root_ca = &pki.ca,
        .now = valid_now,
        .named_groups = &.{ .x25519, .secp256r1 },
        .key_shares = &.{.x25519},
    });
    const outcome = try run.finish(io);
    try outcome.handshake;
    try outcome.echo;
    try testing.expect(seen.retried);
    try testing.expectEqual(proto.NamedGroup.secp256r1, seen.group.?);
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
        var run: Run(lib) = .{};
        try run.start(io, .{
            .gpa = testing.allocator,
            .auth = &pki.server_ec,
            .now = valid_now,
            .client_auth = .{ .root_ca = &pki.ca, .auth_type = case.auth_type },
        });
        const result = clientOnce(lib, &run.loopback, .{
            .gpa = testing.allocator,
            .host = "localhost",
            .root_ca = &pki.ca,
            .now = valid_now,
            .auth = case.client_pair,
        });
        if (case.client_err) |err| try testing.expectError(err, result) else _ = try result;
        const outcome = try run.finish(io);
        if (case.server_err) |err| try testing.expectError(err, outcome.handshake) else try outcome.handshake;
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
    var run: Run(lib) = .{};
    try run.start(io, .{
        .gpa = testing.allocator,
        .auth = &server_pair,
        .now = valid_now,
        .client_auth = .{ .root_ca = &pki.ca, .auth_type = .require },
    });
    _ = try clientOnce(lib, &run.loopback, .{ .gpa = testing.allocator, .host = "localhost", .root_ca = &pki.ca, .now = valid_now, .auth = &client_pair });
    var outcome = try run.finish(io);
    try outcome.handshake;
    try outcome.echo;
    try testing.expectEqual(1, server_signer.calls);
    try testing.expectEqual(1, client_signer.calls);

    // No client certificate asked for: the client's hook stays unused.
    var run2: Run(lib) = .{};
    try run2.start(io, .{ .gpa = testing.allocator, .auth = &server_pair, .now = valid_now });
    _ = try clientOnce(lib, &run2.loopback, .{ .gpa = testing.allocator, .host = "localhost", .root_ca = &pki.ca, .now = valid_now, .auth = &client_pair });
    outcome = try run2.finish(io);
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
    var run3: Run(lib) = .{};
    try run3.start(io, .{ .gpa = testing.allocator, .auth = &server_pair, .now = valid_now });
    try testing.expectError(error.TlsAlertInternalError, clientOnce(lib, &run3.loopback, .{ .gpa = testing.allocator, .host = "localhost", .root_ca = &pki.ca, .now = valid_now }));
    outcome = try run3.finish(io);
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
        var run: Run(lib) = .{};
        try run.start(io, .{ .gpa = testing.allocator, .auth = case.server_pair, .now = valid_now });
        const result = clientOnce(lib, &run.loopback, .{
            .gpa = testing.allocator,
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
    const base_server: config.Server = .{ .gpa = testing.allocator, .auth = &pki.server_ec, .now = valid_now };
    const base_client: config.Client = .{ .gpa = testing.allocator, .host = "localhost", .root_ca = &pki.ca, .now = valid_now };
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
    // P-521 is not among a default client's groups.
    var p521_server = base_server;
    p521_server.named_groups = &.{.secp521r1};
    const cases = [_]Case{
        .{ .server = alpn_server, .client = alpn_client, .client_err = error.TlsAlertNoApplicationProtocol, .server_err = error.TlsNoApplicationProtocol },
        .{ .server = suite_server, .client = suite_client, .client_err = error.TlsAlertHandshakeFailure, .server_err = error.TlsHandshakeFailure },
        .{ .server = group_server, .client = group_client, .client_err = error.TlsAlertHandshakeFailure, .server_err = error.TlsHandshakeFailure },
        .{ .server = p521_server, .client = base_client, .client_err = error.TlsAlertHandshakeFailure, .server_err = error.TlsHandshakeFailure },
    };
    for (cases) |case| {
        var run: Run(lib) = .{};
        try run.start(io, case.server);
        try testing.expectError(case.client_err, clientOnce(lib, &run.loopback, case.client));
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
        var run: Run(lib) = .{};
        try run.start(io, .{ .gpa = testing.allocator, .auth = &pki.server_rsa, .now = valid_now, .signing_schemes = case.server_signing });
        const result = clientOnce(lib, &run.loopback, .{
            .gpa = testing.allocator,
            .host = "localhost",
            .root_ca = &pki.ca,
            .now = valid_now,
            .verify_schemes = case.client_verify,
        });
        const outcome = try run.finish(io);
        if (case.expected) |scheme| {
            const seen = try result;
            try testing.expectEqual(scheme, seen.peer_signature_scheme.?);
            try outcome.handshake;
        } else {
            try testing.expectError(error.TlsAlertHandshakeFailure, result);
            try testing.expectError(error.TlsHandshakeFailure, outcome.handshake);
        }
    }

    // A client certificate the server would not take is left out.
    var run: Run(lib) = .{};
    try run.start(io, .{
        .gpa = testing.allocator,
        .auth = &pki.server_ec,
        .now = valid_now,
        .client_auth = .{ .root_ca = &pki.ca, .auth_type = .require },
        .verify_schemes = &.{.ed25519},
    });
    try testing.expectError(error.TlsAlertCertificateRequired, clientOnce(lib, &run.loopback, .{
        .gpa = testing.allocator,
        .host = "localhost",
        .root_ca = &pki.ca,
        .now = valid_now,
        .auth = &pki.client,
    }));
    const outcome = try run.finish(io);
    try testing.expectError(error.TlsCertificateRequired, outcome.handshake);
}

test "a server without a TLS 1.3 suite or a group ztls knows is refused before anything is read" {
    var pki = try Pki.init();
    defer pki.deinit();
    var input_buffer: [lib.input_buffer_len]u8 = undefined;
    var output_buffer: [lib.output_buffer_len]u8 = undefined;
    const base: config.Server = .{ .gpa = testing.allocator, .auth = &pki.server_ec, .now = valid_now };
    var no_tls13 = base;
    no_tls13.cipher_suites = &proto.CipherSuite.tls12;
    var no_groups = base;
    no_groups.named_groups = &.{};
    var unknown_groups = base;
    unknown_groups.named_groups = &.{ .x448, .ffdhe2048 };
    for ([_]config.Server{ no_tls13, no_groups, unknown_groups }) |opt| {
        var input: Io.Reader = .fixed(&input_buffer);
        var discard: Io.Writer.Discarding = .init(&output_buffer);
        try testing.expectError(error.TlsInternalError, lib.server(&input, &discard.writer, opt));
        try testing.expectEqual(0, discard.count + discard.writer.end);
    }
}

test "a client without a group ztls knows is refused before anything is sent" {
    var input_buffer: [lib.input_buffer_len]u8 = undefined;
    var output_buffer: [lib.output_buffer_len]u8 = undefined;
    const base: config.Client = .{ .gpa = testing.allocator, .host = "localhost", .insecure_skip_verify = true, .now = valid_now };
    var no_groups = base;
    no_groups.named_groups = &.{};
    var unknown_groups = base;
    unknown_groups.named_groups = &.{ .x448, .ffdhe2048 };
    unknown_groups.key_shares = &.{.x448};
    for ([_]config.Client{ no_groups, unknown_groups }) |opt| {
        var input: Io.Reader = .fixed(&input_buffer);
        var discard: Io.Writer.Discarding = .init(&output_buffer);
        try testing.expectError(error.TlsInternalError, lib.client(&input, &discard.writer, opt));
        try testing.expectEqual(0, discard.count + discard.writer.end);
    }
}

test "the native client is refused without a group it has a key exchange for" {
    if (libssl_build) return error.SkipZigTest;
    var input_buffer: [lib.input_buffer_len]u8 = undefined;
    var output_buffer: [lib.output_buffer_len]u8 = undefined;
    var opt: config.Client = .{ .gpa = testing.allocator, .host = "localhost", .insecure_skip_verify = true, .now = valid_now };
    opt.named_groups = &.{.secp521r1};
    opt.key_shares = &.{};
    opt.cipher_suites = &proto.CipherSuite.tls12;
    var input: Io.Reader = .fixed(&input_buffer);
    var discard: Io.Writer.Discarding = .init(&output_buffer);
    try testing.expectError(error.TlsInternalError, lib.client(&input, &discard.writer, opt));
    try testing.expectEqual(0, discard.count + discard.writer.end);
}

test "signature scheme lists must be ones we implement, each once" {
    var input_buffer: [lib.input_buffer_len]u8 = undefined;
    var output_buffer: [lib.output_buffer_len]u8 = undefined;
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
                .client_verify, .client_signing => lib.client(&input, &discard.writer, .{
                    .gpa = testing.allocator,
                    .host = "localhost",
                    .insecure_skip_verify = true,
                    .now = valid_now,
                    .verify_schemes = if (side == .client_verify) schemes else &config.default_signature_schemes,
                    .signing_schemes = if (side == .client_signing) schemes else &config.default_signature_schemes,
                }),
                .server_verify, .server_signing => lib.server(&input, &discard.writer, .{
                    .gpa = testing.allocator,
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
        var run: Run(lib) = .{};
        try run.start(io, .{
            .gpa = testing.allocator,
            .auth = &pki.server_ed25519,
            .certificates = &.{ &pki.server_chain, &pki.server_ec },
            .select_certificate = .{ .context = &picker, .callback = Picker.pick },
            .now = valid_now,
        });
        const seen = try clientOnce(lib, &run.loopback, .{
            .gpa = testing.allocator,
            .host = case.host,
            .root_ca = &pki.ca,
            .insecure_skip_verify = case.skip_verify,
            .now = valid_now,
        });
        try testing.expectEqual(case.key_type, seen.peer_key_type.?);
        const outcome = try run.finish(io);
        try outcome.handshake;
    }
    try testing.expectEqual(cases.len, picker.calls);

    // With no fallback, an unknown name is refused.
    var run: Run(lib) = .{};
    try run.start(io, .{ .gpa = testing.allocator, .auth = null, .certificates = &.{&pki.server_ec}, .now = valid_now });
    try testing.expectError(error.TlsAlertUnrecognizedName, clientOnce(lib, &run.loopback, .{
        .gpa = testing.allocator,
        .host = "nomatch.invalid",
        .root_ca = &pki.ca,
        .now = valid_now,
    }));
    const outcome = try run.finish(io);
    try testing.expectError(error.TlsUnrecognizedName, outcome.handshake);

    // Nor does a server with no certificate at all take any name.
    var bare: Run(lib) = .{};
    try bare.start(io, .{ .gpa = testing.allocator, .auth = null, .now = valid_now });
    try testing.expectError(error.TlsAlertUnrecognizedName, clientOnce(lib, &bare.loopback, .{
        .gpa = testing.allocator,
        .host = "localhost",
        .root_ca = &pki.ca,
        .now = valid_now,
    }));
    const bare_outcome = try bare.finish(io);
    try testing.expectError(error.TlsUnrecognizedName, bare_outcome.handshake);
}

test "select_certificate sees the client's schemes that ztls knows, rsa_pkcs1 ones included" {
    const io = testing.io;
    var pki = try Pki.init();
    defer pki.deinit();
    const Recorder = struct {
        schemes: [8]proto.SignatureScheme = undefined,
        len: usize = 0,

        fn pick(context: ?*anyopaque, hello: config.SelectCertificate.Hello) ?*const CertKeyPair {
            const self: *@This() = @ptrCast(@alignCast(context.?));
            self.len = @min(hello.schemes.len, self.schemes.len);
            @memcpy(self.schemes[0..self.len], hello.schemes[0..self.len]);
            return null;
        }
    };
    var recorder: Recorder = .{};
    var run: Run(lib) = .{};
    try run.start(io, .{
        .gpa = testing.allocator,
        .auth = &pki.server_ec,
        .now = valid_now,
        .select_certificate = .{ .context = &recorder, .callback = Recorder.pick },
    });
    const offered = [_]proto.SignatureScheme{ .rsa_pkcs1_sha256, .ecdsa_secp256r1_sha256 };
    _ = try clientOnce(lib, &run.loopback, .{
        .gpa = testing.allocator,
        .host = "localhost",
        .root_ca = &pki.ca,
        .now = valid_now,
        .verify_schemes = &offered,
    });
    const outcome = try run.finish(io);
    try outcome.handshake;
    try testing.expectEqualSlices(proto.SignatureScheme, &offered, recorder.schemes[0..recorder.len]);
}

test "a Certificate message longer than max_handshake_message_len is refused" {
    const io = testing.io;
    var pki = try Pki.init();
    defer pki.deinit();
    // The leaf, then copies of another certificate the client ignores: a
    // Certificate message of more than 20 KiB. libssl holds every
    // handshake message to at least 16 KiB, so the limit is above that.
    var chain: [40][]const u8 = undefined;
    chain[0] = pki.server_ec.chain[0];
    for (chain[1..]) |*der| der.* = pki.server_rsa.chain[0];
    var big = pki.server_ec;
    big.chain = &chain;
    var len: usize = 0;
    for (chain) |der| len += der.len;
    try testing.expect(len > 20 * 1024);

    {
        var run: Run(lib) = .{};
        try run.start(io, .{ .gpa = testing.allocator, .auth = &big, .now = valid_now });
        try testing.expectError(error.TlsIllegalParameter, clientOnce(lib, &run.loopback, .{
            .gpa = testing.allocator,
            .host = "localhost",
            .root_ca = &pki.ca,
            .now = valid_now,
            .max_handshake_message_len = 20 * 1024,
        }));
        const outcome = try run.finish(io);
        try testing.expectError(error.TlsAlertIllegalParameter, outcome.handshake);
    }
    {
        var run: Run(lib) = .{};
        try run.start(io, .{ .gpa = testing.allocator, .auth = &big, .now = valid_now });
        _ = try clientOnce(lib, &run.loopback, .{
            .gpa = testing.allocator,
            .host = "localhost",
            .root_ca = &pki.ca,
            .now = valid_now,
            .max_handshake_message_len = 64 * 1024,
        });
        const outcome = try run.finish(io);
        try outcome.handshake;
    }
}

test "an empty host is a misconfiguration unless verification is off" {
    var pki = try Pki.init();
    defer pki.deinit();
    // Refused before anything is read or written.
    var input_buffer: [lib.input_buffer_len]u8 = undefined;
    var output_buffer: [lib.output_buffer_len]u8 = undefined;
    var input: Io.Reader = .fixed(&input_buffer);
    var discard: Io.Writer.Discarding = .init(&output_buffer);
    try testing.expectError(error.TlsInternalError, lib.client(&input, &discard.writer, .{
        .gpa = testing.allocator,
        .host = "",
        .root_ca = &pki.ca,
        .now = valid_now,
    }));
    try testing.expectEqual(0, discard.count + discard.writer.end);
}

test "a client held to TLS 1.2 is refused by the TLS 1.3 server" {
    const io = testing.io;
    var pki = try Pki.init();
    defer pki.deinit();
    var run: Run(lib) = .{};
    try run.start(io, .{ .gpa = testing.allocator, .auth = &pki.server_ec, .now = valid_now });
    try testing.expectError(error.TlsAlertProtocolVersion, clientOnce(lib, &run.loopback, .{
        .gpa = testing.allocator,
        .host = "localhost",
        .root_ca = &pki.ca,
        .now = valid_now,
        .cipher_suites = &proto.CipherSuite.tls12,
    }));
    const outcome = try run.finish(io);
    try testing.expectError(error.TlsProtocolVersion, outcome.handshake);
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
        var run: Run(lib) = .{};
        try run.start(io, .{ .gpa = testing.allocator, .auth = &pki.server_ec, .now = valid_now });
        {
            var t: Transport = .{ .io = io, .stream = try run.loopback.connect() };
            defer t.deinit();
            t.setUp();
            try t.sendRaw(bytes);
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
    try testing.expectError(error.EndOfStream, lib.client(&t.input.interface, &t.output.interface, .{ .gpa = testing.allocator, .host = "localhost", .root_ca = &pki.ca, .now = valid_now }));
    try rude.await(io);
}

test "close_notify in place of the ClientHello is the end of the stream, with no alert" {
    const io = testing.io;
    var pki = try Pki.init();
    defer pki.deinit();
    var run: Run(lib) = .{};
    try run.start(io, .{ .gpa = testing.allocator, .auth = &pki.server_ec, .now = valid_now });
    {
        var t: Transport = .{ .io = io, .stream = try run.loopback.connect() };
        defer t.deinit();
        t.setUp();
        try t.sendRaw(&.{ @intFromEnum(proto.ContentType.alert), 3, 3, 0, 2, 1, @intFromEnum(proto.Alert.close_notify) });
        t.stream.shutdown(io, .send) catch {};
        try testing.expectEqual(0, try t.input.interface.discardRemaining());
    }
    const outcome = try run.finish(io);
    try testing.expectError(error.EndOfStream, outcome.handshake);
}

test "a large transfer with key updates both ways" {
    const io = testing.io;
    var pki = try Pki.init();
    defer pki.deinit();

    const Sink = struct {
        /// Reads everything, asking for a KeyUpdate halfway, and sends
        /// back how much came.
        fn serve(loopback: *testu.Loopback, auth: *const CertKeyPair) !void {
            var t: Transport = .{ .io = loopback.io, .stream = try loopback.accept() };
            defer t.deinit();
            t.setUp();
            var conn = try lib.server(&t.input.interface, &t.output.interface, .{ .gpa = testing.allocator, .auth = auth, .now = valid_now });
            defer conn.deinit();
            var rbuf: [4096]u8 = undefined;
            var wbuf: [64]u8 = undefined;
            var r = conn.reader(&rbuf);
            var w = conn.writer(&wbuf);
            var total: usize = 0;
            var asked = false;
            while (true) {
                const n = r.interface.discardShort(64 * 1024) catch |err| return r.err orelse err;
                if (n == 0) break;
                total += n;
                if (!asked and total > 512 * 1024) {
                    try w.requestKeyUpdate();
                    asked = true;
                }
            }
            try w.interface.print("{d}\n", .{total});
            try w.close();
        }
    };

    var loopback = try testu.Loopback.init(io);
    defer loopback.deinit();
    var task = try io.concurrent(Sink.serve, .{ &loopback, &pki.server_ec });
    defer task.cancel(io) catch {};

    var t: Transport = .{ .io = io, .stream = try loopback.connect() };
    defer t.deinit();
    t.setUp();
    var conn = try lib.client(&t.input.interface, &t.output.interface, .{ .gpa = testing.allocator, .host = "localhost", .root_ca = &pki.ca, .now = valid_now });
    defer conn.deinit();
    var wbuf: [8192]u8 = undefined;
    var w = conn.writer(&wbuf);
    var chunk: [1000]u8 = undefined;
    for (&chunk, 0..) |*b, i| b.* = @truncate(i);
    const rounds = 2000;
    for (0..rounds) |i| {
        if (i == rounds / 2) try w.requestKeyUpdate();
        try w.interface.writeAll(&chunk);
    }
    try w.close();
    var rbuf: [64]u8 = undefined;
    var r = conn.reader(&rbuf);
    const line = (try r.interface.takeDelimiter('\n')).?;
    var expected: [32]u8 = undefined;
    try testing.expectEqualStrings(try std.fmt.bufPrint(&expected, "{d}", .{rounds * chunk.len}), line);
    try task.await(io);
}

test "one task reads while another writes, with key updates from both sides" {
    const io = testing.io;
    var pki = try Pki.init();
    defer pki.deinit();
    const lines = 600;

    const Server = struct {
        /// Echoes lines, asking for a KeyUpdate every so often.
        fn serve(loopback: *testu.Loopback, auth: *const CertKeyPair) !void {
            var t: Transport = .{ .io = loopback.io, .stream = try loopback.accept() };
            defer t.deinit();
            t.setUp();
            var conn = try lib.server(&t.input.interface, &t.output.interface, .{ .gpa = testing.allocator, .auth = auth, .now = valid_now });
            defer conn.deinit();
            var rbuf: [1024]u8 = undefined;
            var wbuf: [1024]u8 = undefined;
            var r = conn.reader(&rbuf);
            var w = conn.writer(&wbuf);
            var count: usize = 0;
            while (r.interface.takeDelimiter('\n') catch |err| return r.err orelse err) |line| {
                try w.interface.print("echo: {s}\n", .{line});
                count += 1;
                if (count % 25 == 0) try w.requestKeyUpdate() else try w.interface.flush();
            }
            try w.close();
        }
    };
    const Reading = struct {
        fn run(conn: *lib.Connection) !void {
            var rbuf: [256]u8 = undefined;
            var r = conn.reader(&rbuf);
            for (0..lines) |i| {
                const line = (r.interface.takeDelimiter('\n') catch |err| return r.err orelse err).?;
                var expected: [32]u8 = undefined;
                try testing.expectEqualStrings(try std.fmt.bufPrint(&expected, "echo: line {d}", .{i}), line);
            }
            try testing.expectEqual(null, r.interface.takeDelimiter('\n') catch |err| return r.err orelse err);
        }
    };

    var loopback = try testu.Loopback.init(io);
    defer loopback.deinit();
    var server_task = try io.concurrent(Server.serve, .{ &loopback, &pki.server_ec });
    defer server_task.cancel(io) catch {};

    var t: Transport = .{ .io = io, .stream = try loopback.connect() };
    defer t.deinit();
    t.setUp();
    var conn = try lib.client(&t.input.interface, &t.output.interface, .{ .gpa = testing.allocator, .host = "localhost", .root_ca = &pki.ca, .now = valid_now });
    defer conn.deinit();
    var reading = try io.concurrent(Reading.run, .{&conn});
    defer reading.cancel(io) catch {};

    // The server's KeyUpdate requests reach the reading task, and this
    // one has to answer them.
    var wbuf: [512]u8 = undefined;
    var w = conn.writer(&wbuf);
    for (0..lines) |i| {
        try w.interface.print("line {d}\n", .{i});
        if (i % 10 == 9) try w.interface.flush();
        if (i % 77 == 76) try w.requestKeyUpdate();
    }
    try w.close();
    try reading.await(io);
    try server_task.await(io);
}

/// A transport writer that fails every `fail_every`th call, as a
/// cancelled or timed out write would, and otherwise passes everything
/// on to `inner`.
const Flaky = struct {
    inner: *Io.Writer,
    fail_every: usize = 0,
    calls: usize = 0,
    failures: usize = 0,
    interface: Io.Writer,

    fn init(inner: *Io.Writer, buffer: []u8) Flaky {
        return .{ .inner = inner, .interface = .{ .vtable = &.{ .drain = drain, .flush = flush }, .buffer = buffer, .end = 0 } };
    }

    fn fails(f: *Flaky) bool {
        if (f.fail_every == 0) return false;
        f.calls += 1;
        if (f.calls % f.fail_every != 0) return false;
        f.failures += 1;
        return true;
    }

    fn drain(w: *Io.Writer, data: []const []const u8, splat: usize) Io.Writer.Error!usize {
        const f: *Flaky = @fieldParentPtr("interface", w);
        if (f.fails()) return error.WriteFailed;
        try f.inner.writeAll(w.buffered());
        w.end = 0;
        return f.inner.writeSplat(data, splat);
    }

    fn flush(w: *Io.Writer) Io.Writer.Error!void {
        const f: *Flaky = @fieldParentPtr("interface", w);
        if (f.fails()) return error.WriteFailed;
        try f.inner.writeAll(w.buffered());
        w.end = 0;
        try f.inner.flush();
    }
};

test "writes, flushes, key updates and close may be retried after the transport fails" {
    const io = testing.io;
    var pki = try Pki.init();
    defer pki.deinit();
    const rounds = 300;
    const Hash = std.crypto.hash.sha2.Sha256;

    // The bytes of round `i`, of a length that varies around the
    // buffers' sizes.
    const Data = struct {
        fn fill(buf: []u8, i: usize) []u8 {
            const len = 1 + (i * 977) % buf.len;
            for (buf[0..len], 0..) |*b, j| b.* = @truncate(i * 31 + j);
            return buf[0..len];
        }
    };
    const Server = struct {
        /// Reads everything to a close_notify, then reports what came.
        fn serve(loopback: *testu.Loopback, context: struct { auth: *const CertKeyPair, digest: *[Hash.digest_length]u8 }) !void {
            var t: Transport = .{ .io = loopback.io, .stream = try loopback.accept() };
            defer t.deinit();
            t.setUp();
            var conn = try lib.server(&t.input.interface, &t.output.interface, .{ .gpa = testing.allocator, .auth = context.auth, .now = valid_now, .strict_close_notify = true });
            defer conn.deinit();
            var rbuf: [4096]u8 = undefined;
            var r = conn.reader(&rbuf);
            var hash: Hash = .init(.{});
            var chunk: [3000]u8 = undefined;
            while (true) {
                const n = r.interface.readSliceShort(&chunk) catch return r.err.?;
                if (n == 0) break;
                hash.update(chunk[0..n]);
            }
            hash.final(context.digest);
        }
    };

    var digest: [Hash.digest_length]u8 = undefined;
    var loopback = try testu.Loopback.init(io);
    defer loopback.deinit();
    var task = try io.concurrent(Server.serve, .{ &loopback, .{ .auth = &pki.server_ec, .digest = &digest } });
    defer task.cancel(io) catch {};

    var t: Transport = .{ .io = io, .stream = try loopback.connect() };
    defer t.deinit();
    t.setUp();
    var flaky_buffer: [lib.output_buffer_len]u8 = undefined;
    var flaky: Flaky = .init(&t.output.interface, &flaky_buffer);
    var conn = try lib.client(&t.input.interface, &flaky.interface, .{ .gpa = testing.allocator, .host = "localhost", .root_ca = &pki.ca, .now = valid_now });
    defer conn.deinit();
    flaky.fail_every = 3;

    var wbuf: [1000]u8 = undefined;
    var w = conn.writer(&wbuf);
    const W = @TypeOf(w);
    const Retry = struct {
        /// Runs `op` until the transport lets it through.
        fn retry(writer: *W, comptime op: anytype, args: anytype) !void {
            while (true) {
                if (@call(.auto, op, args)) |_| return else |_| {}
                if (writer.err.? != error.WriteFailed) return writer.err.?;
            }
        }
        fn flush(writer: *W) Io.Writer.Error!void {
            return writer.interface.flush();
        }
    };
    var sent: Hash = .init(.{});
    var bytes: [5000]u8 = undefined;
    for (0..rounds) |i| {
        const data = Data.fill(&bytes, i);
        sent.update(data);
        var at: usize = 0;
        while (at < data.len) {
            at += w.interface.write(data[at..]) catch {
                if (w.err.? != error.WriteFailed) return w.err.?;
                continue;
            };
        }
        if (i % 5 == 4) try Retry.retry(&w, Retry.flush, .{&w});
        if (i % 17 == 16) try Retry.retry(&w, W.requestKeyUpdate, .{&w});
    }
    try Retry.retry(&w, W.close, .{&w});
    try testing.expect(flaky.failures > 10);
    t.lingerClose();
    try task.await(io);
    try testing.expectEqual(sent.finalResult(), digest);
}

/// A record that cannot be opened.
const garbage = [_]u8{ @intFromEnum(proto.ContentType.application_data), 3, 3, 0, 32 } ++ @as([32]u8, @splat(0xaa));

test "a record that fails to open ends the read side, and the write side sends the alert" {
    const io = testing.io;
    var pki = try Pki.init();
    defer pki.deinit();

    const Server = struct {
        fn serve(loopback: *testu.Loopback, context: struct { auth: *const CertKeyPair, half_closed: bool }) !void {
            var t: Transport = .{ .io = loopback.io, .stream = try loopback.accept() };
            defer t.deinit();
            t.setUp();
            var conn = try lib.server(&t.input.interface, &t.output.interface, .{ .gpa = testing.allocator, .auth = context.auth, .now = valid_now });
            defer conn.deinit();
            var rbuf: [64]u8 = undefined;
            var wbuf: [64]u8 = undefined;
            var r = conn.reader(&rbuf);
            var w = conn.writer(&wbuf);
            // After close_notify no alert can go out, but the read side
            // still says what it found.
            if (context.half_closed) try w.close();
            try testing.expectError(error.ReadFailed, r.interface.takeByte());
            try testing.expectEqual(error.TlsBadRecordMac, r.err.?);
            try testing.expectError(error.ReadFailed, r.interface.takeByte());
            try testing.expectEqual(error.TlsConnectionFailed, r.err.?);
            if (context.half_closed) return;
            // The write side sends the alert and fails as the read did,
            // then as a failed connection.
            try w.interface.writeAll("late");
            try testing.expectError(error.WriteFailed, w.interface.flush());
            try testing.expectEqual(error.TlsBadRecordMac, w.err.?);
            try w.interface.writeAll("later");
            try testing.expectError(error.WriteFailed, w.interface.flush());
            try testing.expectEqual(error.TlsConnectionFailed, w.err.?);
        }
    };

    for ([_]bool{ false, true }) |half_closed| {
        var loopback = try testu.Loopback.init(io);
        defer loopback.deinit();
        var task = try io.concurrent(Server.serve, .{ &loopback, .{ .auth = &pki.server_ec, .half_closed = half_closed } });
        defer task.cancel(io) catch {};
        var t: Transport = .{ .io = io, .stream = try loopback.connect() };
        defer t.deinit();
        t.setUp();
        var conn = try lib.client(&t.input.interface, &t.output.interface, .{ .gpa = testing.allocator, .host = "localhost", .root_ca = &pki.ca, .now = valid_now });
        defer conn.deinit();
        try t.sendRaw(&garbage);
        var rbuf: [64]u8 = undefined;
        var r = conn.reader(&rbuf);
        if (half_closed) {
            try testing.expectError(error.EndOfStream, r.interface.takeByte());
        } else {
            try testing.expectError(error.ReadFailed, r.interface.takeByte());
            try testing.expectEqual(error.TlsAlertBadRecordMac, r.err.?);
        }
        t.lingerClose();
        try task.await(io);
    }
}

test "the transport ending: inside a record, between records, and without close_notify when it is required" {
    const io = testing.io;
    var pki = try Pki.init();
    defer pki.deinit();

    const Case = struct { raw: []const u8, strict: bool, read_err: ?anyerror };
    const Server = struct {
        fn serve(loopback: *testu.Loopback, context: struct { auth: *const CertKeyPair, case: Case }) !void {
            var t: Transport = .{ .io = loopback.io, .stream = try loopback.accept() };
            defer t.deinit();
            t.setUp();
            var conn = try lib.server(&t.input.interface, &t.output.interface, .{
                .gpa = testing.allocator,
                .auth = context.auth,
                .now = valid_now,
                .strict_close_notify = context.case.strict,
            });
            defer conn.deinit();
            var rbuf: [64]u8 = undefined;
            var wbuf: [64]u8 = undefined;
            var r = conn.reader(&rbuf);
            var w = conn.writer(&wbuf);
            if (context.case.read_err) |expected| {
                try testing.expectError(error.ReadFailed, r.interface.takeByte());
                try testing.expectEqual(expected, r.err.?);
                // Truncation ends the write side too.
                try w.interface.writeAll("late");
                try testing.expectError(error.WriteFailed, w.interface.flush());
                try testing.expectEqual(expected, w.err.?);
            } else {
                // A clean end is a half-close: writing goes on.
                try testing.expectError(error.EndOfStream, r.interface.takeByte());
                try w.interface.writeAll("still here");
                try w.close();
            }
        }
    };

    for ([_]Case{
        .{ .raw = garbage[0..3], .strict = false, .read_err = error.TlsConnectionTruncated },
        .{ .raw = "", .strict = false, .read_err = null },
        .{ .raw = "", .strict = true, .read_err = error.TlsConnectionTruncated },
    }) |case| {
        var loopback = try testu.Loopback.init(io);
        defer loopback.deinit();
        var task = try io.concurrent(Server.serve, .{ &loopback, .{ .auth = &pki.server_ec, .case = case } });
        defer task.cancel(io) catch {};
        var t: Transport = .{ .io = io, .stream = try loopback.connect() };
        defer t.deinit();
        t.setUp();
        var conn = try lib.client(&t.input.interface, &t.output.interface, .{ .gpa = testing.allocator, .host = "localhost", .root_ca = &pki.ca, .now = valid_now });
        defer conn.deinit();
        try t.sendRaw(case.raw);
        t.lingerClose();
        try task.await(io);
    }
}

/// What a misbehaving native peer sends once its handshake is done: a
/// record sealed with its keys, or bytes as they are.
const Misdeed = union(enum) {
    sealed: struct { content_type: proto.ContentType = .handshake, payload: []const u8 },
    raw: []const u8,
};

/// How the end under test must take a peer's misdeeds.
const Verdict = union(enum) {
    /// Its reader fails with this, and its writer sends the alert for it
    /// and fails the same way.
    refused: api.Failure,
    /// It reads these lines, then the end of the stream, and closes.
    accepted: []const []const u8,
};

/// `native` or `libssl` as the implementation under test refuses it:
/// where AWS-LC's libssl picks another alert than the native code, which
/// the wrapper cannot change.
fn refusedAs(native_err: api.Failure, libssl_err: api.Failure) Verdict {
    return .{ .refused = if (libssl_build) libssl_err else native_err };
}

/// Runs the end under test as `side` against a native peer, which
/// completes the handshake, sends `misdeeds`, then nothing more.
fn expectVerdict(io: Io, pki: *const Pki, side: proto.Side, misdeeds: []const Misdeed, verdict: Verdict) !void {
    const Peer = struct {
        fn run(loopback: *testu.Loopback, p: *const Pki, peer_side: proto.Side, m: []const Misdeed, v: Verdict) !void {
            var t: Transport = .{ .io = loopback.io, .stream = if (peer_side == .server) try loopback.accept() else try loopback.connect() };
            defer t.deinit();
            t.setUp();
            const in = &t.input.interface;
            const out = &t.output.interface;
            var conn = if (peer_side == .server)
                try native.server(in, out, .{ .gpa = testing.allocator, .auth = &p.server_ec, .now = valid_now })
            else
                try native.client(in, out, .{ .gpa = testing.allocator, .host = "localhost", .root_ca = &p.ca, .now = valid_now });
            defer conn.deinit();
            for (m) |misdeed| switch (misdeed) {
                .sealed => |record| {
                    const keys = &conn.write.keys.?;
                    const len = keys.sealedLen(record.payload.len);
                    const buf = try out.writableSliceGreedy(len);
                    @memcpy(buf[keys.payloadOffset()..][0..record.payload.len], record.payload);
                    try keys.seal(buf[0..len], record.content_type, record.payload.len);
                    out.advance(len);
                },
                .raw => |bytes| try out.writeAll(bytes),
            };
            try out.flush();
            // Nothing follows: an end that waits for more sees the
            // transport end rather than hanging the test.
            try t.stream.shutdown(t.io, .send);
            var rbuf: [256]u8 = undefined;
            var r = conn.reader(&rbuf);
            switch (v) {
                .refused => |err| {
                    try testing.expectError(error.ReadFailed, r.interface.takeDelimiter('\n'));
                    try testing.expectEqual(proto.Alert.forLocalError(err).?.toError().?, r.err.?);
                },
                .accepted => try testing.expectEqual(null, try r.interface.takeDelimiter('\n')),
            }
        }
    };
    var loopback = try testu.Loopback.init(io);
    defer loopback.deinit();
    var peer = try io.concurrent(Peer.run, .{ &loopback, pki, if (side == .client) proto.Side.server else .client, misdeeds, verdict });
    defer peer.cancel(io) catch {};

    var t: Transport = .{ .io = io, .stream = if (side == .server) try loopback.accept() else try loopback.connect() };
    defer t.deinit();
    t.setUp();
    const in = &t.input.interface;
    const out = &t.output.interface;
    var conn = if (side == .server)
        try lib.server(in, out, .{ .gpa = testing.allocator, .auth = &pki.server_ec, .now = valid_now })
    else
        try lib.client(in, out, .{ .gpa = testing.allocator, .host = "localhost", .root_ca = &pki.ca, .now = valid_now });
    defer conn.deinit();
    var rbuf: [256]u8 = undefined;
    var r = conn.reader(&rbuf);
    var w = conn.writer(&.{});
    switch (verdict) {
        .refused => |err| {
            try testing.expectError(error.ReadFailed, r.interface.takeDelimiter('\n'));
            try testing.expectEqual(err, r.err.?);
            try testing.expectError(error.WriteFailed, w.interface.writeAll("x"));
            try testing.expectEqual(err, w.err.?);
        },
        .accepted => |lines| {
            for (lines) |line| try testing.expectEqualStrings(line, (try r.interface.takeDelimiter('\n')).?);
            try testing.expectEqual(null, try r.interface.takeDelimiter('\n'));
            try w.close();
        },
    }
    try peer.await(io);
}

const nst = @intFromEnum(proto.HandshakeType.new_session_ticket);
const ku = @intFromEnum(proto.HandshakeType.key_update);

test "malformed post-handshake messages" {
    const io = testing.io;
    var pki = try Pki.init();
    defer pki.deinit();
    const Case = struct { side: proto.Side = .client, misdeeds: []const Misdeed, verdict: Verdict };
    const cases = [_]Case{
        // A KeyUpdate with a two-byte body.
        .{ .misdeeds = &.{.{ .sealed = .{ .payload = &.{ ku, 0, 0, 2, 0, 0 } } }}, .verdict = .{ .refused = error.TlsDecodeError } },
        // A KeyUpdate that does not end its record.
        .{ .misdeeds = &.{.{ .sealed = .{ .payload = &.{ ku, 0, 0, 1, 0, nst } } }}, .verdict = .{ .refused = error.TlsUnexpectedMessage } },
        // A request that is neither. RFC 8446 §4.6.3 calls for
        // illegal_parameter; AWS-LC sends decode_error.
        .{ .misdeeds = &.{.{ .sealed = .{ .payload = &.{ ku, 0, 0, 1, 2 } } }}, .verdict = refusedAs(error.TlsIllegalParameter, error.TlsDecodeError) },
        // A ticket longer than a handshake message may be.
        .{ .misdeeds = &.{.{ .sealed = .{ .payload = &.{ nst, 0xff, 0xff, 0xff } } }}, .verdict = .{ .refused = error.TlsIllegalParameter } },
        // A ticket shorter than any can be.
        .{ .misdeeds = &.{.{ .sealed = .{ .payload = &([_]u8{ nst, 0, 0, 13 } ++ @as([13]u8, @splat(0))) } }}, .verdict = .{ .refused = error.TlsDecodeError } },
        // A message only a handshake has.
        .{ .misdeeds = &.{.{ .sealed = .{ .payload = &.{ @intFromEnum(proto.HandshakeType.finished), 0, 0, 0 } } }}, .verdict = .{ .refused = error.TlsUnexpectedMessage } },
        // Application data between a message's pieces.
        .{ .misdeeds = &.{ .{ .sealed = .{ .payload = &.{ nst, 0, 0, 14, 0 } } }, .{ .sealed = .{ .content_type = .application_data, .payload = "x" } } }, .verdict = .{ .refused = error.TlsUnexpectedMessage } },
        // A ticket sent to a server.
        .{ .side = .server, .misdeeds = &.{.{ .sealed = .{ .payload = &.{ nst, 0, 0, 0 } } }}, .verdict = .{ .refused = error.TlsUnexpectedMessage } },
    };
    for (cases) |case| try expectVerdict(io, &pki, case.side, case.misdeeds, case.verdict);
}

test "an empty handshake record, and an end inside a post-handshake message, are taken as BoringSSL takes them" {
    const io = testing.io;
    var pki = try Pki.init();
    defer pki.deinit();
    // A peer must not send an empty handshake record (RFC 8446 §5.1), but
    // it changes nothing.
    try expectVerdict(io, &pki, .client, &.{
        .{ .sealed = .{ .payload = &.{} } },
        .{ .sealed = .{ .content_type = .application_data, .payload = "hi\n" } },
    }, .{ .accepted = &.{"hi"} });
    // What close_notify or the transport's end cuts off carries no data
    // and changes no keys.
    try expectVerdict(io, &pki, .client, &.{
        .{ .sealed = .{ .payload = &.{ ku, 0 } } },
        .{ .sealed = .{ .content_type = .alert, .payload = &.{ 1, 0 } } },
    }, .{ .accepted = &.{} });
    try expectVerdict(io, &pki, .client, &.{
        .{ .sealed = .{ .payload = &.{ ku, 0 } } },
    }, .{ .accepted = &.{} });
}

test "records that cannot come after the handshake" {
    const io = testing.io;
    var pki = try Pki.init();
    defer pki.deinit();
    const handshake = @intFromEnum(proto.ContentType.handshake);
    const ccs = @intFromEnum(proto.ContentType.change_cipher_spec);
    const Case = struct { bytes: []const u8, verdict: Verdict };
    const cases = [_]Case{
        // Not a content type. AWS-LC looks at the version field first.
        .{ .bytes = &.{ 0x80, 0x2e, 0x01, 0x03, 0x03 }, .verdict = refusedAs(error.TlsUnexpectedMessage, error.TlsProtocolVersion) },
        // A handshake record or change_cipher_spec in the clear, which
        // RFC 8446 §5 refuses with unexpected_message. AWS-LC opens every
        // record after the handshake before it looks at the type.
        .{ .bytes = &([_]u8{ handshake, 3, 3, 0, 32 } ++ @as([32]u8, @splat(0xaa))), .verdict = refusedAs(error.TlsUnexpectedMessage, error.TlsBadRecordMac) },
        .{ .bytes = &.{ ccs, 3, 3, 0, 1, 1 }, .verdict = refusedAs(error.TlsUnexpectedMessage, error.TlsBadRecordMac) },
        // Longer than any protected record: refused from the header.
        .{ .bytes = &.{ @intFromEnum(proto.ContentType.application_data), 3, 3, 0x41, 0x41 }, .verdict = .{ .refused = error.TlsRecordOverflow } },
    };
    for (cases) |case| try expectVerdict(io, &pki, .client, &.{.{ .raw = case.bytes }}, case.verdict);
}

test "a KeyUpdate request made while a reply is owed still reaches the peer" {
    const io = testing.io;
    var pki = try Pki.init();
    defer pki.deinit();

    // The native peer asks for an update, so the end under test owes a
    // reply when it asks for one in turn: both must reach the peer, which
    // answers the request with an update of its own.
    const Peer = struct {
        fn run(loopback: *testu.Loopback, p: *const Pki) !void {
            var t: Transport = .{ .io = loopback.io, .stream = try loopback.accept() };
            defer t.deinit();
            t.setUp();
            var conn = try native.server(&t.input.interface, &t.output.interface, .{ .gpa = testing.allocator, .auth = &p.server_ec, .now = valid_now });
            defer conn.deinit();
            var rbuf: [256]u8 = undefined;
            var r = conn.reader(&rbuf);
            var w = conn.writer(&.{});
            try w.requestKeyUpdate();
            try w.interface.writeAll("ping\n");
            try w.interface.flush();
            try testing.expectEqualStrings("pong", (try r.interface.takeDelimiter('\n')).?);
            try testing.expectEqual(2, conn.keyUpdatesReceived());
            try w.interface.writeAll("done\n");
            try w.interface.flush();
            try testing.expectEqual(2, conn.keyUpdatesSent());
            try testing.expectEqual(null, try r.interface.takeDelimiter('\n'));
            try w.close();
        }
    };
    var loopback = try testu.Loopback.init(io);
    defer loopback.deinit();
    var peer = try io.concurrent(Peer.run, .{ &loopback, &pki });
    defer peer.cancel(io) catch {};

    var t: Transport = .{ .io = io, .stream = try loopback.connect() };
    defer t.deinit();
    t.setUp();
    var conn = try lib.client(&t.input.interface, &t.output.interface, .{ .gpa = testing.allocator, .host = "localhost", .root_ca = &pki.ca, .now = valid_now });
    defer conn.deinit();
    var rbuf: [256]u8 = undefined;
    var r = conn.reader(&rbuf);
    var w = conn.writer(&.{});
    try testing.expectEqualStrings("ping", (try r.interface.takeDelimiter('\n')).?);
    try w.requestKeyUpdate();
    try w.interface.writeAll("pong\n");
    try w.interface.flush();
    try testing.expectEqual(2, conn.keyUpdatesSent());
    try testing.expectEqualStrings("done", (try r.interface.takeDelimiter('\n')).?);
    try testing.expectEqual(2, conn.keyUpdatesReceived());
    try w.close();
    try testing.expectEqual(null, try r.interface.takeDelimiter('\n'));
    try peer.await(io);
}

test "a flush with nothing written sends the KeyUpdate reply a read left owing" {
    // Native answers only with the next record it writes.
    if (!libssl_build) return error.SkipZigTest;
    const io = testing.io;
    var pki = try Pki.init();
    defer pki.deinit();

    // The native peer asks for an update; libssl reads, then only
    // flushes and hangs up without close_notify. The reply must have gone
    // out with that flush.
    const Peer = struct {
        fn run(loopback: *testu.Loopback, p: *const Pki) !void {
            var t: Transport = .{ .io = loopback.io, .stream = try loopback.accept() };
            defer t.deinit();
            t.setUp();
            var conn = try native.server(&t.input.interface, &t.output.interface, .{ .gpa = testing.allocator, .auth = &p.server_ec, .now = valid_now });
            defer conn.deinit();
            var rbuf: [256]u8 = undefined;
            var r = conn.reader(&rbuf);
            var w = conn.writer(&.{});
            try w.requestKeyUpdate();
            try w.interface.writeAll("ping\n");
            try w.interface.flush();
            try testing.expectEqual(null, try r.interface.takeDelimiter('\n'));
            try testing.expectEqual(1, conn.keyUpdatesReceived());
        }
    };
    var loopback = try testu.Loopback.init(io);
    defer loopback.deinit();
    var peer = try io.concurrent(Peer.run, .{ &loopback, &pki });
    defer peer.cancel(io) catch {};

    var t: Transport = .{ .io = io, .stream = try loopback.connect() };
    defer t.deinit();
    t.setUp();
    var conn = try lib.client(&t.input.interface, &t.output.interface, .{ .gpa = testing.allocator, .host = "localhost", .root_ca = &pki.ca, .now = valid_now });
    defer conn.deinit();
    var rbuf: [256]u8 = undefined;
    var r = conn.reader(&rbuf);
    var w = conn.writer(&.{});
    try testing.expectEqualStrings("ping", (try r.interface.takeDelimiter('\n')).?);
    try w.interface.flush();
    try t.stream.shutdown(io, .send);
    try peer.await(io);
}

test "libssl and native talk to each other, each as client and as server" {
    if (!libssl_build) return error.SkipZigTest;
    const io = testing.io;
    var pki = try Pki.init();
    defer pki.deinit();
    const server_options: config.Server = .{ .gpa = testing.allocator, .auth = &pki.server_ec, .now = valid_now, .alpn_protocols = &.{"h2"} };
    const client_options: config.Client = .{ .gpa = testing.allocator, .host = "localhost", .root_ca = &pki.ca, .now = valid_now, .alpn_protocols = &.{"h2"} };
    {
        var run: Run(native) = .{};
        try run.start(io, server_options);
        const seen = try clientOnce(lib, &run.loopback, client_options);
        const outcome = try run.finish(io);
        try outcome.handshake;
        try outcome.echo;
        try testing.expectEqualStrings("h2", seen.alpn.?);
    }
    {
        var run: Run(lib) = .{};
        try run.start(io, server_options);
        const seen = try clientOnce(native, &run.loopback, client_options);
        const outcome = try run.finish(io);
        try outcome.handshake;
        try outcome.echo;
        try testing.expectEqualStrings("h2", seen.alpn.?);
    }
    // A refusal says the same across the two.
    {
        var run: Run(native) = .{};
        try run.start(io, .{ .gpa = testing.allocator, .auth = &pki.selfsigned, .now = valid_now });
        try testing.expectError(error.CertificateIssuerNotFound, clientOnce(lib, &run.loopback, client_options));
        const outcome = try run.finish(io);
        try testing.expectError(error.TlsAlertUnknownCa, outcome.handshake);
    }
    {
        var run: Run(lib) = .{};
        try run.start(io, .{ .gpa = testing.allocator, .auth = &pki.selfsigned, .now = valid_now });
        try testing.expectError(error.CertificateIssuerNotFound, clientOnce(native, &run.loopback, client_options));
        const outcome = try run.finish(io);
        try testing.expectError(error.TlsAlertUnknownCa, outcome.handshake);
    }
}
