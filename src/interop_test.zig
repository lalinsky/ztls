//! Interoperability with OpenSSL, driven as child processes: our client
//! against `s_server`, our server against `s_client`. Skipped when there
//! is no OpenSSL 1.1.1+ on the PATH, and on Windows.

const std = @import("std");
const builtin = @import("builtin");
const Io = std.Io;
const ztls = @import("root.zig");
const config = ztls.config;
const testu = @import("testu.zig");

const testing = std.testing;
const pki = "src/testdata/pki/";
/// Within the test PKI's validity (2027-01-15).
const valid_now: Io.Timestamp = .{ .nanoseconds = 1_800_000_000 * std.time.ns_per_s };

fn spawn(io: Io, argv: []const []const u8, stdin: std.process.SpawnOptions.StdIo, stdout: std.process.SpawnOptions.StdIo) !std.process.Child {
    return std.process.spawn(io, .{ .argv = argv, .stdin = stdin, .stdout = stdout, .stderr = .ignore }) catch |err| switch (err) {
        error.FileNotFound => error.SkipZigTest,
        else => err,
    };
}

/// Skips the test unless a usable OpenSSL is around.
fn requireOpenSsl(io: Io) !void {
    if (builtin.os.tag == .windows) return error.SkipZigTest;
    var child = try spawn(io, &.{ "openssl", "version" }, .ignore, .pipe);
    var buffer: [256]u8 = undefined;
    var reader = child.stdout.?.reader(io, &buffer);
    const line = reader.interface.takeDelimiter('\n') catch null;
    const ok = if (line) |l| std.mem.startsWith(u8, l, "OpenSSL 3") or std.mem.startsWith(u8, l, "OpenSSL 1.1.1") else false;
    child.stdout.?.close(io);
    child.stdout = null;
    if (!exitedCleanly(try child.wait(io)) or !ok) return error.SkipZigTest;
}

fn exitedCleanly(term: std.process.Child.Term) bool {
    return switch (term) {
        .exited => |code| code == 0,
        else => false,
    };
}

/// A port nothing listens on right now.
fn freePort(io: Io) !u16 {
    const address = try Io.net.IpAddress.parse("127.0.0.1", 0);
    var server = try address.listen(io, .{});
    defer server.deinit(io);
    return server.socket.address.getPort();
}

/// Connects once the child listens. The connection that succeeds is the
/// one used: a probe would be the single connection `-naccept 1` allows.
fn connectWhenListening(io: Io, port: u16) !Io.net.Stream {
    const address = try Io.net.IpAddress.parse("127.0.0.1", port);
    const pause: Io.Clock.Duration = .{ .raw = .fromMilliseconds(20), .clock = .awake };
    var tries: usize = 0;
    while (true) : (tries += 1) {
        return address.connect(io, .{ .mode = .stream }) catch |err| switch (err) {
            error.ConnectionRefused => if (tries == 250) return err else {
                try pause.sleep(io);
                continue;
            },
            else => return err,
        };
    }
}

/// Our end's transport, pinned in place.
const Transport = struct {
    io: Io,
    stream: Io.net.Stream,
    input_buffer: [ztls.input_buffer_len]u8 = undefined,
    output_buffer: [ztls.output_buffer_len]u8 = undefined,
    input: Io.net.Stream.Reader = undefined,
    output: Io.net.Stream.Writer = undefined,

    fn setUp(t: *Transport) void {
        t.input = t.stream.reader(t.io, &t.input_buffer);
        t.output = t.stream.writer(t.io, &t.output_buffer);
    }
};

test "our client against openssl s_server" {
    const io = testing.io;
    try requireOpenSsl(io);

    const Case = struct {
        cert: []const u8,
        server_alpn: ?[]const u8 = null,
        client_alpn: []const []const u8 = &.{},
        expected_alpn: ?[]const u8 = null,
        client_cert: bool = false,
        /// Server groups; "P-256" makes OpenSSL retry, since we send no
        /// P-256 share by default.
        groups: ?[]const u8 = null,
    };
    const cases = [_]Case{
        .{ .cert = "server-ec", .server_alpn = "h2,http/1.1", .client_alpn = &.{ "http/1.1", "h2" }, .expected_alpn = "h2" },
        .{ .cert = "server-rsa" },
        .{ .cert = "server-ed25519" },
        .{ .cert = "server-ec", .client_cert = true },
        .{ .cert = "server-ec", .groups = "P-256" },
        .{ .cert = "server-ec", .groups = "X25519" },
    };
    var trust = try ztls.TrustStore.init();
    defer trust.deinit();
    _ = try trust.addPem(testing.allocator, @embedFile("testdata/pki/ca.pem"));
    var client_pair = try ztls.CertKeyPair.fromSlice(testing.allocator, @embedFile("testdata/pki/client.pem"), @embedFile("testdata/pki/client.key"));
    defer client_pair.deinit();

    for (cases) |case| {
        const port = try freePort(io);
        var port_buf: [32]u8 = undefined;
        const accept = try std.fmt.bufPrint(&port_buf, "127.0.0.1:{d}", .{port});
        var cert_buf: [128]u8 = undefined;
        var key_buf: [128]u8 = undefined;
        var argv: std.ArrayList([]const u8) = .empty;
        defer argv.deinit(testing.allocator);
        try argv.appendSlice(testing.allocator, &.{
            "openssl",                                                       "s_server",
            "-accept",                                                       accept,
            "-tls1_3",                                                       "-rev",
            "-naccept",                                                      "1",
            "-quiet",                                                        "-cert",
            try std.fmt.bufPrint(&cert_buf, pki ++ "{s}.pem", .{case.cert}), "-key",
            try std.fmt.bufPrint(&key_buf, pki ++ "{s}.key", .{case.cert}),
        });
        if (case.server_alpn) |alpn| try argv.appendSlice(testing.allocator, &.{ "-alpn", alpn });
        if (case.client_cert) try argv.appendSlice(testing.allocator, &.{ "-Verify", "1", "-CAfile", pki ++ "ca.pem" });
        if (case.groups) |groups| try argv.appendSlice(testing.allocator, &.{ "-groups", groups });

        var child = try spawn(io, argv.items, .ignore, .ignore);
        errdefer child.kill(io);

        var t: Transport = .{ .io = io, .stream = try connectWhenListening(io, port) };
        defer t.stream.close(io);
        t.setUp();
        var conn = try ztls.client(&t.input.interface, &t.output.interface, .{
            .allocator = testing.allocator,
            .host = "localhost",
            .root_ca = &trust,
            .now = valid_now,
            .alpn_protocols = case.client_alpn,
            .auth = if (case.client_cert) &client_pair else null,
        });
        defer conn.deinit();
        if (case.expected_alpn) |alpn| try testing.expectEqualStrings(alpn, conn.alpn_protocol.?) else try testing.expectEqual(null, conn.alpn_protocol);

        var rbuf: [256]u8 = undefined;
        var r = conn.reader(&rbuf);
        var w = conn.inPlaceWriter();
        try w.interface.writeAll("hello openssl\n");
        try w.interface.flush();
        try testing.expectEqualStrings("lssnepo olleh", (try r.interface.takeDelimiter('\n')).?);
        try conn.close();
        try testing.expectEqual(null, try r.interface.takeDelimiter('\n'));
        try testing.expect(exitedCleanly(try child.wait(io)));
    }
}

/// What our server saw.
const Outcome = struct {
    handshake: ztls.Error!void = {},
    alpn: ?[]const u8 = null,
    echo: anyerror!void = {},
};

fn serveOnce(loopback: *testu.Loopback, options: config.Server, outcome: *Outcome) anyerror!void {
    var t: Transport = .{ .io = loopback.io, .stream = try loopback.accept() };
    defer t.stream.close(t.io);
    t.setUp();
    var conn = ztls.server(&t.input.interface, &t.output.interface, options) catch |err| {
        outcome.handshake = err;
        return;
    };
    defer conn.deinit();
    outcome.alpn = conn.alpn_protocol;
    outcome.echo = echo(&conn);
}

fn echo(conn: *ztls.Connection) !void {
    var rbuf: [1024]u8 = undefined;
    var r = conn.reader(&rbuf);
    var w = conn.inPlaceWriter();
    while (r.interface.takeDelimiter('\n') catch |err| return r.err orelse err) |line| {
        try w.interface.print("echo: {s}\n", .{line});
        try w.interface.flush();
    }
    try conn.close();
}

test "openssl s_client against our server" {
    const io = testing.io;
    try requireOpenSsl(io);

    const Case = struct {
        cert: *const ztls.CertKeyPair,
        server_alpn: []const []const u8 = &.{},
        client_alpn: ?[]const u8 = null,
        expected_alpn: ?[]const u8 = null,
        client_auth: ?config.ClientAuth = null,
        client_cert: bool = false,
        /// Client groups; with "X25519:P-256" OpenSSL shares only X25519,
        /// so a server wanting P-256 makes it retry.
        groups: ?[]const u8 = null,
        server_groups: ?[]const ztls.protocol.NamedGroup = null,
    };
    var trust = try ztls.TrustStore.init();
    defer trust.deinit();
    _ = try trust.addPem(testing.allocator, @embedFile("testdata/pki/ca.pem"));
    var ec = try ztls.CertKeyPair.fromSlice(testing.allocator, @embedFile("testdata/pki/server-ec.pem"), @embedFile("testdata/pki/server-ec.key"));
    defer ec.deinit();
    var rsa = try ztls.CertKeyPair.fromSlice(testing.allocator, @embedFile("testdata/pki/server-rsa.pem"), @embedFile("testdata/pki/server-rsa.key"));
    defer rsa.deinit();
    var chain = try ztls.CertKeyPair.fromSlice(testing.allocator, @embedFile("testdata/pki/server-chain.pem"), @embedFile("testdata/pki/server-chain.key"));
    defer chain.deinit();
    const cases = [_]Case{
        .{ .cert = &ec, .server_alpn = &.{ "h2", "http/1.1" }, .client_alpn = "http/1.1,h2", .expected_alpn = "h2" },
        .{ .cert = &rsa },
        .{ .cert = &chain },
        .{ .cert = &ec, .client_auth = .{ .root_ca = &trust, .auth_type = .require }, .client_cert = true },
        .{ .cert = &ec, .groups = "X25519:P-256", .server_groups = &.{.secp256r1} },
        .{ .cert = &ec, .groups = "P-384" },
    };

    for (cases) |case| {
        var loopback = try testu.Loopback.init(io);
        defer loopback.deinit();
        var outcome: Outcome = .{};
        var options: config.Server = .{
            .allocator = testing.allocator,
            .auth = case.cert,
            .now = valid_now,
            .alpn_protocols = case.server_alpn,
            .client_auth = case.client_auth,
        };
        if (case.server_groups) |groups| options.named_groups = groups;
        var task = try io.concurrent(serveOnce, .{ &loopback, options, &outcome });
        defer task.cancel(io) catch {};

        var port_buf: [32]u8 = undefined;
        const connect = try std.fmt.bufPrint(&port_buf, "127.0.0.1:{d}", .{loopback.server.socket.address.getPort()});
        var argv: std.ArrayList([]const u8) = .empty;
        defer argv.deinit(testing.allocator);
        try argv.appendSlice(testing.allocator, &.{
            "openssl",       "s_client",
            "-connect",      connect,
            "-tls1_3",       "-quiet",
            "-no_ign_eof",   "-CAfile",
            pki ++ "ca.pem", "-verify_return_error",
            "-servername",   "localhost",
        });
        if (case.client_alpn) |alpn| try argv.appendSlice(testing.allocator, &.{ "-alpn", alpn });
        if (case.client_cert) try argv.appendSlice(testing.allocator, &.{ "-cert", pki ++ "client.pem", "-key", pki ++ "client.key" });
        if (case.groups) |groups| try argv.appendSlice(testing.allocator, &.{ "-groups", groups });

        var child = try spawn(io, argv.items, .pipe, .pipe);
        errdefer child.kill(io);
        {
            var wbuf: [64]u8 = undefined;
            var stdin = child.stdin.?.writer(io, &wbuf);
            try stdin.interface.writeAll("hello ztls\n");
            try stdin.interface.flush();
        }
        var rbuf: [256]u8 = undefined;
        var stdout = child.stdout.?.reader(io, &rbuf);
        try testing.expectEqualStrings("echo: hello ztls", (try stdout.interface.takeDelimiter('\n')).?);
        // Closing its stdin makes s_client end the connection.
        child.stdin.?.close(io);
        child.stdin = null;
        try testing.expectEqual(null, try stdout.interface.takeDelimiter('\n'));
        child.stdout.?.close(io);
        child.stdout = null;
        try testing.expect(exitedCleanly(try child.wait(io)));

        try task.await(io);
        try outcome.handshake;
        try outcome.echo;
        if (case.expected_alpn) |alpn| try testing.expectEqualStrings(alpn, outcome.alpn.?) else try testing.expectEqual(null, outcome.alpn);
    }
}
