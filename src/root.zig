//! ztls: TLS 1.3 on AWS-LC's libcrypto. See DESIGN.md.
//!
//! `client` and `server` run a handshake over a transport's reader and
//! writer and return a `Connection`, whose `reader`, `writer` and
//! `inPlaceWriter` carry cleartext.

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

pub const Connection = connection.Connection;
pub const TrustStore = config.TrustStore;
pub const CertKeyPair = config.CertKeyPair;
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
    var conn = Connection.init(input, output);
    errdefer conn.deinit();
    try handshake_client.run(&conn, options);
    return conn;
}

/// Runs the server side of a handshake over `input` and `output`.
pub fn server(input: *Io.Reader, output: *Io.Writer, options: config.Server) Error!Connection {
    var conn = Connection.init(input, output);
    errdefer conn.deinit();
    try handshake_server.run(&conn, options);
    return conn;
}

test {
    std.testing.refAllDecls(@This());
    _ = @import("interop_test.zig");
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
        _ = try ca.addPem(testing.allocator, @embedFile("testdata/pki/ca.pem"));
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
        p.server_ec.deinit();
        p.server_rsa.deinit();
        p.server_ed25519.deinit();
        p.server_chain.deinit();
        p.client.deinit();
        p.selfsigned.deinit();
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
    var w = conn.inPlaceWriter();
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
    var w = conn.inPlaceWriter();
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
        .{ .auth_type = .require, .client_pair = &pki.selfsigned, .client_err = error.TlsAlertUnknownCa, .server_err = error.TlsUnknownCa },
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

test "the client refuses a certificate it cannot trust, and tells the server" {
    const io = testing.io;
    var pki = try Pki.init();
    defer pki.deinit();

    const Case = struct { server_pair: *const CertKeyPair, host: []const u8, now: Io.Timestamp, skip_verify: bool = false, client_err: ?anyerror, server_err: ?anyerror };
    const cases = [_]Case{
        .{ .server_pair = &pki.selfsigned, .host = "localhost", .now = valid_now, .client_err = error.TlsUnknownCa, .server_err = error.TlsAlertUnknownCa },
        .{ .server_pair = &pki.server_ec, .host = "example.org", .now = valid_now, .client_err = error.TlsBadCertificate, .server_err = error.TlsAlertBadCertificate },
        .{ .server_pair = &pki.server_ec, .host = "localhost", .now = .{ .nanoseconds = 1_000_000_000 * std.time.ns_per_s }, .client_err = error.TlsCertificateExpired, .server_err = error.TlsAlertCertificateExpired },
        .{ .server_pair = &pki.selfsigned, .host = "localhost", .now = valid_now, .skip_verify = true, .client_err = null, .server_err = null },
        .{ .server_pair = &pki.server_ec, .host = "127.0.0.1", .now = valid_now, .client_err = null, .server_err = null },
        .{ .server_pair = &pki.server_ec, .host = "10.0.0.1", .now = valid_now, .client_err = error.TlsBadCertificate, .server_err = error.TlsAlertBadCertificate },
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

test "a peer that hangs up during the handshake" {
    const io = testing.io;
    var pki = try Pki.init();
    defer pki.deinit();
    var loopback = try testu.Loopback.init(io);
    defer loopback.deinit();

    const Rude = struct {
        fn run(l: *testu.Loopback) !void {
            const stream = try l.accept();
            stream.close(l.io);
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
