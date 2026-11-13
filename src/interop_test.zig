//! Interoperability with other implementations, driven as child
//! processes: OpenSSL's `s_server` and `s_client`, and a Go echo peer
//! (tests/go/echo) that brings X25519MLKEM768, which OpenSSL before 3.5
//! lacks. Each is skipped when its tool is not on the PATH, and all of
//! them on Windows. They run against the implementation being built
//! (`-Dimpl`).

const std = @import("std");
const builtin = @import("builtin");
const Io = std.Io;
const build_options = @import("build_options");
const libssl_build = build_options.libssl;
/// The implementation under test.
const ztls = if (libssl_build) @import("root_libssl.zig") else @import("root_native.zig");
const config = ztls.config;
const proto = ztls.protocol;
const testu = @import("testu.zig");

const testing = std.testing;
const pki = "src/testdata/pki/";
/// A stuck exchange is killed after this long, so a bug fails a test
/// rather than hanging it.
const watchdog_seconds = 60;

/// A child process with a watchdog. Pipes are closed and the watchdog
/// stopped before the child is waited for or killed, in that order,
/// because `kill` and `wait` may not race and `kill` after `wait` expects
/// the pipes gone.
const Peer = struct {
    io: Io,
    child: std.process.Child,
    watchdog: Io.Future(Io.Cancelable!void),
    timed_out: bool = false,

    fn spawn(io: Io, argv: []const []const u8, stdin: std.process.SpawnOptions.StdIo, stdout: std.process.SpawnOptions.StdIo) !*Peer {
        const peer = try testing.allocator.create(Peer);
        errdefer testing.allocator.destroy(peer);
        peer.* = .{
            .io = io,
            .child = std.process.spawn(io, .{ .argv = argv, .stdin = stdin, .stdout = stdout, .stderr = .ignore }) catch |err| switch (err) {
                error.FileNotFound => return error.SkipZigTest,
                else => return err,
            },
            .watchdog = undefined,
        };
        errdefer peer.child.kill(io);
        peer.watchdog = try io.concurrent(watch, .{peer});
        return peer;
    }

    fn watch(peer: *Peer) Io.Cancelable!void {
        const limit: Io.Clock.Duration = .{ .raw = .fromSeconds(watchdog_seconds), .clock = .awake };
        try limit.sleep(peer.io);
        peer.timed_out = true;
        peer.child.kill(peer.io);
    }

    fn closePipes(peer: *Peer) void {
        if (peer.child.stdin) |f| f.close(peer.io);
        peer.child.stdin = null;
        if (peer.child.stdout) |f| f.close(peer.io);
        peer.child.stdout = null;
    }

    /// Waits for a clean exit.
    fn finish(peer: *Peer) !void {
        defer testing.allocator.destroy(peer);
        peer.closePipes();
        peer.watchdog.cancel(peer.io) catch {};
        if (peer.timed_out) return error.Timeout;
        const term = try peer.child.wait(peer.io);
        switch (term) {
            .exited => |code| if (code != 0) return error.PeerFailed,
            else => return error.PeerFailed,
        }
    }

    /// Ends the child without caring how it goes, on a failed test.
    fn abort(peer: *Peer) void {
        defer testing.allocator.destroy(peer);
        peer.closePipes();
        peer.watchdog.cancel(peer.io) catch {};
        peer.child.kill(peer.io);
    }
};

/// The first line of a child's stdout.
fn firstLine(peer: *Peer, buffer: []u8) ![]const u8 {
    var reader = peer.child.stdout.?.reader(peer.io, buffer);
    const line = (try reader.interface.takeDelimiter('\n')) orelse return error.PeerSaidNothing;
    // The reader's buffer is the caller's; what follows the line is lost,
    // so only the first line of a chatty program can be read this way.
    return line;
}

/// Skips the test unless OpenSSL 1.1.1+ is around; returns its version
/// line.
fn requireOpenSsl(io: Io) ![]const u8 {
    if (builtin.os.tag == .windows) return error.SkipZigTest;
    const peer = try Peer.spawn(io, &.{ "openssl", "version" }, .ignore, .pipe);
    // Until `finish`, which frees the peer whether or not it fails.
    var peer_running = true;
    errdefer if (peer_running) peer.abort();
    const S = struct {
        var line_buf: [256]u8 = undefined;
    };
    const line = try firstLine(peer, &S.line_buf);
    peer_running = false;
    try peer.finish();
    if (!std.mem.startsWith(u8, line, "OpenSSL 3") and !std.mem.startsWith(u8, line, "OpenSSL 1.1.1")) return error.SkipZigTest;
    return line;
}

fn requireGo(io: Io) !void {
    if (builtin.os.tag == .windows) return error.SkipZigTest;
    const peer = try Peer.spawn(io, &.{ "go", "version" }, .ignore, .ignore);
    // `finish` frees the peer whether or not it fails.
    peer.finish() catch return error.SkipZigTest;
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

/// A cleartext writer that encrypts in place where the implementation
/// can.
fn writerOf(conn: *ztls.Connection, buffer: []u8) ztls.Connection.Writer {
    return if (@hasDecl(ztls.Connection, "writerInPlace")) conn.writerInPlace() else conn.writer(buffer);
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

/// The pattern's letters leave out k, K, Q and R: `s_client` takes a
/// chunk of stdin that starts with one of them as a command and drops it.
const pattern_letters = "acdefghijlmnopstuvwxyz";

/// Lines of a pattern, `total` bytes of them, written through `w`; the
/// reader checks them with `expectPattern`.
fn writePattern(w: *Io.Writer, total: usize) !void {
    var written: usize = 0;
    var i: usize = 0;
    while (written < total) : (i += 1) {
        var line: [64]u8 = undefined;
        const s = try std.fmt.bufPrint(&line, "line {d} {s}\n", .{ i, pattern_letters[0 .. i % (pattern_letters.len + 1)] });
        try w.writeAll(s);
        written += s.len;
    }
    try w.flush();
}

/// Reads the pattern back, each line transformed by `transform`.
fn expectPattern(r: *Io.Reader, total: usize, transform: enum { echo, reversed }) !void {
    var consumed: usize = 0;
    var i: usize = 0;
    while (consumed < total) : (i += 1) {
        var line: [64]u8 = undefined;
        const s = try std.fmt.bufPrint(&line, "line {d} {s}", .{ i, pattern_letters[0 .. i % (pattern_letters.len + 1)] });
        consumed += s.len + 1;
        const got = (try r.takeDelimiter('\n')) orelse return error.EndOfStream;
        switch (transform) {
            .echo => {
                try testing.expect(std.mem.startsWith(u8, got, "echo: "));
                try testing.expectEqualStrings(s, got["echo: ".len..]);
            },
            .reversed => {
                std.mem.reverse(u8, s);
                try testing.expectEqualStrings(s, got);
            },
        }
    }
}

test "our client against openssl s_server" {
    const io = testing.io;
    _ = try requireOpenSsl(io);

    const Case = struct {
        cert: []const u8 = "server-ec",
        server_alpn: ?[]const u8 = null,
        client_alpn: []const []const u8 = &.{},
        expected_alpn: ?[]const u8 = null,
        client_cert: bool = false,
        /// Server groups; "P-256" makes OpenSSL retry, since we send no
        /// P-256 share by default.
        groups: ?[]const u8 = null,
        /// OpenSSL's suite names; ours are restricted to match.
        ciphersuites: ?[]const u8 = null,
        suites: []const proto.CipherSuite = &proto.CipherSuite.all,
        /// Ask OpenSSL for a key update mid-way and go on.
        key_update: bool = false,
        /// Bytes to push through in each direction, concurrently.
        transfer: usize = 0,
        /// The server speaks TLS 1.2 only; we offer both versions.
        tls12: bool = false,
        /// OpenSSL's TLS 1.2 suite names, and signature algorithms.
        cipher: ?[]const u8 = null,
        sigalgs: ?[]const u8 = null,
        /// Ask for a client certificate without requiring one.
        request_cert: bool = false,
    };
    const both = proto.CipherSuite.all ++ proto.CipherSuite.tls12;
    const cases = [_]Case{
        .{ .server_alpn = "h2,http/1.1", .client_alpn = &.{ "http/1.1", "h2" }, .expected_alpn = "h2" },
        .{ .cert = "server-rsa" },
        .{ .cert = "server-ed25519" },
        .{ .client_cert = true },
        .{ .groups = "P-256" },
        .{ .groups = "X25519" },
        .{ .ciphersuites = "TLS_CHACHA20_POLY1305_SHA256", .suites = &.{.chacha20_poly1305_sha256} },
        .{ .ciphersuites = "TLS_AES_128_GCM_SHA256", .suites = &.{.aes_128_gcm_sha256} },
        .{ .key_update = true },
        .{ .transfer = 1 << 20 },
        // TLS 1.2: ECDHE_ECDSA with the default suite, curve and hash.
        .{ .tls12 = true, .suites = &both, .server_alpn = "h2,http/1.1", .client_alpn = &.{ "http/1.1", "h2" }, .expected_alpn = "h2" },
        // ECDHE_RSA signed with RSA-PSS, and with PKCS#1 v1.5.
        .{ .tls12 = true, .suites = &both, .cert = "server-rsa", .cipher = "ECDHE-RSA-AES256-GCM-SHA384" },
        .{ .tls12 = true, .suites = &both, .cert = "server-rsa", .sigalgs = "RSA+SHA256" },
        .{ .tls12 = true, .suites = &both, .cert = "server-rsa", .sigalgs = "RSA+SHA512", .cipher = "ECDHE-RSA-CHACHA20-POLY1305" },
        .{ .tls12 = true, .suites = &both, .cert = "server-ed25519" },
        .{ .tls12 = true, .suites = &both, .cipher = "ECDHE-ECDSA-CHACHA20-POLY1305", .groups = "P-256" },
        .{ .tls12 = true, .suites = &both, .cipher = "ECDHE-ECDSA-AES256-GCM-SHA384", .groups = "P-384" },
        .{ .tls12 = true, .suites = &proto.CipherSuite.tls12, .request_cert = true },
        // A client certificate, required, under both suite kinds.
        .{ .tls12 = true, .suites = &both, .client_cert = true },
        .{ .tls12 = true, .suites = &both, .client_cert = true, .cert = "server-rsa", .sigalgs = "RSA+SHA256:ECDSA+SHA384" },
        .{ .tls12 = true, .suites = &both, .transfer = 1 << 20 },
    };
    var trust = try ztls.TrustStore.init();
    defer trust.deinit();
    try trust.addPem(testing.allocator, @embedFile("testdata/pki/ca.pem"));
    var client_pair = try ztls.CertKeyPair.fromSlice(testing.allocator, @embedFile("testdata/pki/client.pem"), @embedFile("testdata/pki/client.key"));
    defer client_pair.deinit(testing.allocator);

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
            if (case.tls12) "-tls1_2" else "-tls1_3",                        "-rev",
            "-naccept",                                                      "1",
            "-quiet",                                                        "-cert",
            try std.fmt.bufPrint(&cert_buf, pki ++ "{s}.pem", .{case.cert}), "-key",
            try std.fmt.bufPrint(&key_buf, pki ++ "{s}.key", .{case.cert}),
        });
        if (case.server_alpn) |alpn| try argv.appendSlice(testing.allocator, &.{ "-alpn", alpn });
        if (case.client_cert) try argv.appendSlice(testing.allocator, &.{ "-Verify", "1", "-CAfile", pki ++ "ca.pem" });
        if (case.groups) |groups| try argv.appendSlice(testing.allocator, &.{ "-groups", groups });
        if (case.ciphersuites) |suites| try argv.appendSlice(testing.allocator, &.{ "-ciphersuites", suites });
        if (case.cipher) |cipher| try argv.appendSlice(testing.allocator, &.{ "-cipher", cipher });
        if (case.sigalgs) |sigalgs| try argv.appendSlice(testing.allocator, &.{ "-sigalgs", sigalgs });
        if (case.request_cert) try argv.appendSlice(testing.allocator, &.{ "-verify", "1", "-CAfile", pki ++ "ca.pem" });

        const peer = try Peer.spawn(io, argv.items, .ignore, .ignore);
        // Until `finish`, which frees the peer whether or not it fails.
        var peer_running = true;
        errdefer if (peer_running) peer.abort();

        var t: Transport = .{ .io = io, .stream = try connectWhenListening(io, port) };
        defer t.stream.close(io);
        t.setUp();
        var conn = try ztls.client(&t.input.interface, &t.output.interface, .{
            .io = testing.io,
            .gpa = testing.allocator,
            .host = "localhost",
            .root_ca = &trust,
            .alpn_protocols = case.client_alpn,
            .auth = if (case.client_cert) &client_pair else null,
            .cipher_suites = case.suites,
        });
        defer conn.deinit();
        if (case.expected_alpn) |alpn| try testing.expectEqualStrings(alpn, conn.alpn_protocol.?) else try testing.expectEqual(null, conn.alpn_protocol);
        try testing.expectEqual(if (case.tls12) proto.Version.tls_1_2 else .tls_1_3, conn.version.?);

        var rbuf: [256]u8 = undefined;
        var r = conn.reader(&rbuf);
        var wbuf: [1024]u8 = undefined;
        var w = writerOf(&conn, &wbuf);
        try w.interface.writeAll("hello openssl\n");
        try w.interface.flush();
        try testing.expectEqualStrings("lssnepo olleh", (try r.interface.takeDelimiter('\n')).?);

        if (case.key_update) {
            // We update and ask; OpenSSL must answer with its own update
            // before its next record, which the reply below is.
            const before = conn.keyUpdatesReceived();
            try w.requestKeyUpdate();
            try w.interface.writeAll("after update\n");
            try w.interface.flush();
            try testing.expectEqualStrings("etadpu retfa", (try r.interface.takeDelimiter('\n')).?);
            try testing.expect(conn.keyUpdatesReceived() > before);
        }
        if (case.transfer > 0) {
            var sender = try io.concurrent(writePattern, .{ &w.interface, case.transfer });
            defer sender.cancel(io) catch {};
            try expectPattern(&r.interface, case.transfer, .reversed);
            try sender.await(io);
        }
        try conn.close();
        try testing.expectEqual(null, try r.interface.takeDelimiter('\n'));
        peer_running = false;
        try peer.finish();
    }
}

/// What our server saw.
const Outcome = struct {
    handshake: ztls.Error!void = {},
    alpn: ?[]const u8 = null,
    peer_key_type: ?ztls.crypto.sig.KeyType = null,
    /// Whether the peer updated its keys at least once.
    read_keys_updated: bool = false,
    version: ?proto.Version = null,
    suite: ?proto.CipherSuite = null,
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
    outcome.peer_key_type = conn.peer_key_type;
    outcome.version = conn.version;
    outcome.suite = conn.suite;
    outcome.echo = echo(&conn);
    outcome.read_keys_updated = conn.keyUpdatesReceived() > 0;
}

fn echo(conn: *ztls.Connection) !void {
    var rbuf: [1024]u8 = undefined;
    var r = conn.reader(&rbuf);
    var wbuf: [1024]u8 = undefined;
    var w = writerOf(conn, &wbuf);
    while (r.interface.takeDelimiter('\n') catch |err| return r.err orelse err) |line| {
        try w.interface.print("echo: {s}\n", .{line});
        try w.interface.flush();
    }
    try conn.close();
}

test "openssl s_client against our server" {
    const io = testing.io;
    _ = try requireOpenSsl(io);

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
        server_groups: ?[]const proto.NamedGroup = null,
        ciphersuites: ?[]const u8 = null,
        suites: []const proto.CipherSuite = &proto.CipherSuite.all,
        /// Have s_client update its keys and ask us to: "K" on stdin.
        key_update: bool = false,
        transfer: usize = 0,
    };
    var trust = try ztls.TrustStore.init();
    defer trust.deinit();
    try trust.addPem(testing.allocator, @embedFile("testdata/pki/ca.pem"));
    var ec = try ztls.CertKeyPair.fromSlice(testing.allocator, @embedFile("testdata/pki/server-ec.pem"), @embedFile("testdata/pki/server-ec.key"));
    defer ec.deinit(testing.allocator);
    var rsa = try ztls.CertKeyPair.fromSlice(testing.allocator, @embedFile("testdata/pki/server-rsa.pem"), @embedFile("testdata/pki/server-rsa.key"));
    defer rsa.deinit(testing.allocator);
    var chain = try ztls.CertKeyPair.fromSlice(testing.allocator, @embedFile("testdata/pki/server-chain.pem"), @embedFile("testdata/pki/server-chain.key"));
    defer chain.deinit(testing.allocator);
    const cases = [_]Case{
        .{ .cert = &ec, .server_alpn = &.{ "h2", "http/1.1" }, .client_alpn = "http/1.1,h2", .expected_alpn = "h2" },
        .{ .cert = &rsa },
        .{ .cert = &chain },
        .{ .cert = &ec, .client_auth = .{ .root_ca = &trust, .auth_type = .require }, .client_cert = true },
        .{ .cert = &ec, .groups = "X25519:P-256", .server_groups = &.{.secp256r1} },
        .{ .cert = &ec, .groups = "P-384" },
        .{ .cert = &ec, .ciphersuites = "TLS_CHACHA20_POLY1305_SHA256", .suites = &.{.chacha20_poly1305_sha256} },
        .{ .cert = &ec, .ciphersuites = "TLS_AES_128_GCM_SHA256", .suites = &.{.aes_128_gcm_sha256} },
        .{ .cert = &ec, .key_update = true },
        .{ .cert = &ec, .transfer = 1 << 20 },
    };

    for (cases) |case| {
        var loopback = try testu.Loopback.init(io);
        defer loopback.deinit();
        var outcome: Outcome = .{};
        var options: config.Server = .{
            .io = testing.io,
            .gpa = testing.allocator,
            .auth = case.cert,
            .alpn_protocols = case.server_alpn,
            .client_auth = case.client_auth,
            .cipher_suites = case.suites,
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
        if (case.ciphersuites) |suites| try argv.appendSlice(testing.allocator, &.{ "-ciphersuites", suites });

        const peer = try Peer.spawn(io, argv.items, .pipe, .pipe);
        // Until `finish`, which frees the peer whether or not it fails.
        var peer_running = true;
        errdefer if (peer_running) peer.abort();
        var wbuf: [1024]u8 = undefined;
        var stdin = peer.child.stdin.?.writer(io, &wbuf);
        var rbuf: [1024]u8 = undefined;
        var stdout = peer.child.stdout.?.reader(io, &rbuf);

        try stdin.interface.writeAll("hello ztls\n");
        try stdin.interface.flush();
        try testing.expectEqualStrings("echo: hello ztls", (try stdout.interface.takeDelimiter('\n')).?);
        if (case.key_update) {
            // s_client takes a line of "K" as: update keys and request
            // an update back.
            // s_client takes the whole chunk it reads as the command, so
            // the data must arrive in a later read.
            try stdin.interface.writeAll("K\n");
            try stdin.interface.flush();
            const pause: Io.Clock.Duration = .{ .raw = .fromMilliseconds(200), .clock = .awake };
            try pause.sleep(io);
            try stdin.interface.writeAll("after update\n");
            try stdin.interface.flush();
            const reply = (try stdout.interface.takeDelimiter('\n')) orelse return error.ConnectionEnded;
            try testing.expectEqualStrings("echo: after update", reply);
        }
        if (case.transfer > 0) {
            var sender = try io.concurrent(writePattern, .{ &stdin.interface, case.transfer });
            defer sender.cancel(io) catch {};
            try expectPattern(&stdout.interface, case.transfer, .echo);
            try sender.await(io);
        }
        // Closing its stdin makes s_client end the connection.
        peer.child.stdin.?.close(io);
        peer.child.stdin = null;
        try testing.expectEqual(null, try stdout.interface.takeDelimiter('\n'));
        peer_running = false;
        try peer.finish();

        try task.await(io);
        try outcome.handshake;
        try outcome.echo;
        if (case.expected_alpn) |alpn| try testing.expectEqualStrings(alpn, outcome.alpn.?) else try testing.expectEqual(null, outcome.alpn);
        if (case.client_cert) try testing.expectEqual(ztls.crypto.sig.KeyType{ .ecdsa = .p256 }, outcome.peer_key_type.?);
        try testing.expectEqual(case.key_update, outcome.read_keys_updated);
    }
}

/// A peer held to a version or suite that only libssl speaks: TLS 1.2
/// with CBC or RSA key exchange, or TLS 1.1 and 1.0, which OpenSSL 3
/// allows only at security level 0.
const LegacyCase = struct {
    /// OpenSSL's version flag and suite.
    flag: []const u8,
    cipher: []const u8,
    cert: []const u8,
    version: proto.Version,
    suite: proto.CipherSuite,
    /// What the native client gets from a server it cannot talk to.
    native_err: anyerror,
};

const legacy_cases = [_]LegacyCase{
    .{ .flag = "-tls1_2", .cipher = "AES128-SHA", .cert = "server-rsa", .version = .tls_1_2, .suite = @enumFromInt(0x002f), .native_err = error.TlsAlertHandshakeFailure },
    .{ .flag = "-tls1_2", .cipher = "ECDHE-ECDSA-AES128-SHA", .cert = "server-ec", .version = .tls_1_2, .suite = @enumFromInt(0xc009), .native_err = error.TlsAlertHandshakeFailure },
    .{ .flag = "-tls1_1", .cipher = "ECDHE-RSA-AES128-SHA:@SECLEVEL=0", .cert = "server-rsa", .version = .tls_1_1, .suite = @enumFromInt(0xc013), .native_err = error.TlsAlertProtocolVersion },
    .{ .flag = "-tls1", .cipher = "AES256-SHA:@SECLEVEL=0", .cert = "server-rsa", .version = .tls_1_0, .suite = @enumFromInt(0x0035), .native_err = error.TlsAlertProtocolVersion },
};

/// What our client settled with an `openssl s_server`.
const ClientSeen = struct {
    version: proto.Version,
    suite: proto.CipherSuite,
    peer_signature_scheme: ?proto.SignatureScheme,
};

/// Connects our client to `openssl s_server` with `args` added, once,
/// and exchanges a line with it.
fn sServerOnce(io: Io, cert: []const u8, args: []const []const u8, options: config.Client) !ClientSeen {
    const port = try freePort(io);
    var port_buf: [32]u8 = undefined;
    const accept = try std.fmt.bufPrint(&port_buf, "127.0.0.1:{d}", .{port});
    var cert_buf: [128]u8 = undefined;
    var key_buf: [128]u8 = undefined;
    var argv: std.ArrayList([]const u8) = .empty;
    defer argv.deinit(testing.allocator);
    try argv.appendSlice(testing.allocator, &.{
        "openssl", "s_server",                                                 "-accept", accept,
        "-rev",    "-naccept",                                                 "1",       "-quiet",
        "-cert",   try std.fmt.bufPrint(&cert_buf, pki ++ "{s}.pem", .{cert}), "-key",    try std.fmt.bufPrint(&key_buf, pki ++ "{s}.key", .{cert}),
    });
    try argv.appendSlice(testing.allocator, args);
    const peer = try Peer.spawn(io, argv.items, .ignore, .ignore);
    // Until `finish`, which frees the peer whether or not it fails.
    var peer_running = true;
    errdefer if (peer_running) peer.abort();

    var t: Transport = .{ .io = io, .stream = try connectWhenListening(io, port) };
    defer t.stream.close(io);
    t.setUp();
    var conn = try ztls.client(&t.input.interface, &t.output.interface, options);
    defer conn.deinit();
    var rbuf: [256]u8 = undefined;
    var r = conn.reader(&rbuf);
    var wbuf: [1024]u8 = undefined;
    var w = writerOf(&conn, &wbuf);
    try w.interface.writeAll("hello openssl\n");
    try w.interface.flush();
    try testing.expectEqualStrings("lssnepo olleh", (try r.interface.takeDelimiter('\n')).?);
    try conn.close();
    try testing.expectEqual(null, try r.interface.takeDelimiter('\n'));
    peer_running = false;
    try peer.finish();
    return .{ .version = conn.version.?, .suite = conn.suite.?, .peer_signature_scheme = conn.peer_signature_scheme };
}

/// Serves `openssl s_client` with `args` added, once. A line goes back
/// and forth if the handshake succeeds; `echoed` says whether it did.
fn sClientOnce(io: Io, options: config.Server, args: []const []const u8) !struct { outcome: Outcome, echoed: bool } {
    var loopback = try testu.Loopback.init(io);
    defer loopback.deinit();
    var outcome: Outcome = .{};
    var task = try io.concurrent(serveOnce, .{ &loopback, options, &outcome });
    defer task.cancel(io) catch {};

    var port_buf: [32]u8 = undefined;
    const connect = try std.fmt.bufPrint(&port_buf, "127.0.0.1:{d}", .{loopback.server.socket.address.getPort()});
    var argv: std.ArrayList([]const u8) = .empty;
    defer argv.deinit(testing.allocator);
    try argv.appendSlice(testing.allocator, &.{
        "openssl",     "s_client",    "-connect", connect,
        "-quiet",      "-no_ign_eof", "-CAfile",  pki ++ "ca.pem",
        "-servername", "localhost",
    });
    try argv.appendSlice(testing.allocator, args);
    const peer = try Peer.spawn(io, argv.items, .pipe, .pipe);
    // Until `finish`, which frees the peer whether or not it fails.
    var peer_running = true;
    errdefer if (peer_running) peer.abort();
    var wbuf: [1024]u8 = undefined;
    var stdin = peer.child.stdin.?.writer(io, &wbuf);
    var rbuf: [1024]u8 = undefined;
    var stdout = peer.child.stdout.?.reader(io, &rbuf);

    // A failed handshake ends s_client, so these may find it gone.
    stdin.interface.writeAll("hello ztls\n") catch {};
    stdin.interface.flush() catch {};
    const line = stdout.interface.takeDelimiter('\n') catch null;
    const echoed = if (line) |l| std.mem.eql(u8, l, "echo: hello ztls") else false;
    // Closing its stdin makes s_client end the connection.
    peer.child.stdin.?.close(io);
    peer.child.stdin = null;
    while (stdout.interface.takeDelimiter('\n') catch null) |_| {}
    peer_running = false;
    // s_client fails with the handshake; the outcome says how. One that
    // failed before connecting would leave the server waiting to accept:
    // a connection that closes at once fails its handshake instead.
    peer.finish() catch {
        if (loopback.connect()) |stream| stream.close(io) else |_| {}
    };
    try task.await(io);
    return .{ .outcome = outcome, .echoed = echoed };
}

test "our client against a legacy openssl s_server: libssl connects, native refuses" {
    const io = testing.io;
    _ = try requireOpenSsl(io);
    var trust = try ztls.TrustStore.init();
    defer trust.deinit();
    try trust.addPem(testing.allocator, @embedFile("testdata/pki/ca.pem"));
    const options: config.Client = .{ .io = testing.io, .gpa = testing.allocator, .host = "localhost", .root_ca = &trust };

    for (legacy_cases) |case| {
        const result = sServerOnce(io, case.cert, &.{ case.flag, "-cipher", case.cipher }, options);
        if (!libssl_build) {
            try testing.expectError(case.native_err, result);
            continue;
        }
        const seen = try result;
        try testing.expectEqual(case.version, seen.version);
        try testing.expectEqual(case.suite, seen.suite);
    }
}

test "a TLS 1.2 server that signs with SHA-1 only: libssl takes it by default, native when asked" {
    const io = testing.io;
    _ = try requireOpenSsl(io);
    var trust = try ztls.TrustStore.init();
    defer trust.deinit();
    try trust.addPem(testing.allocator, @embedFile("testdata/pki/ca.pem"));
    const args: []const []const u8 = &.{ "-tls1_2", "-sigalgs", "RSA+SHA1", "-cipher", "ECDHE-RSA-AES128-GCM-SHA256:@SECLEVEL=0" };
    var options: config.Client = .{ .io = testing.io, .gpa = testing.allocator, .host = "localhost", .root_ca = &trust };
    if (libssl_build) {
        const seen = try sServerOnce(io, "server-rsa", args, options);
        try testing.expectEqual(proto.SignatureScheme.rsa_pkcs1_sha1, seen.peer_signature_scheme.?);
    } else {
        try testing.expect(std.meta.isError(sServerOnce(io, "server-rsa", args, options)));
    }
    options.verify_schemes = &config.known_signature_schemes;
    const seen = try sServerOnce(io, "server-rsa", args, options);
    try testing.expectEqual(proto.SignatureScheme.rsa_pkcs1_sha1, seen.peer_signature_scheme.?);
}

test "the libssl client: a version range, and an Ed25519 certificate it cannot sign with before TLS 1.2" {
    if (!libssl_build) return error.SkipZigTest;
    const io = testing.io;
    _ = try requireOpenSsl(io);
    var trust = try ztls.TrustStore.init();
    defer trust.deinit();
    try trust.addPem(testing.allocator, @embedFile("testdata/pki/ca.pem"));
    var options: config.Client = .{ .io = testing.io, .gpa = testing.allocator, .host = "localhost", .root_ca = &trust };

    // Held to TLS 1.3, against a TLS 1.2 server.
    options.min_version = .tls_1_3;
    try testing.expectError(error.TlsAlertProtocolVersion, sServerOnce(io, "server-ec", &.{"-tls1_2"}, options));
    options.min_version = null;

    // Asked for a certificate by a TLS 1.1 server that does not require
    // one: an Ed25519 key cannot sign there, so none goes out.
    var ed = try ztls.CertKeyPair.fromSlice(testing.allocator, @embedFile("testdata/pki/server-ed25519.pem"), @embedFile("testdata/pki/server-ed25519.key"));
    defer ed.deinit(testing.allocator);
    options.auth = &ed;
    const seen = try sServerOnce(io, "server-rsa", &.{ "-tls1_1", "-cipher", "ECDHE-RSA-AES128-SHA:@SECLEVEL=0", "-verify", "1", "-CAfile", pki ++ "ca.pem" }, options);
    try testing.expectEqual(proto.Version.tls_1_1, seen.version);
}

test "a legacy openssl s_client against our libssl server" {
    if (!libssl_build) return error.SkipZigTest;
    const io = testing.io;
    _ = try requireOpenSsl(io);
    var ec = try ztls.CertKeyPair.fromSlice(testing.allocator, @embedFile("testdata/pki/server-ec.pem"), @embedFile("testdata/pki/server-ec.key"));
    defer ec.deinit(testing.allocator);
    var rsa = try ztls.CertKeyPair.fromSlice(testing.allocator, @embedFile("testdata/pki/server-rsa.pem"), @embedFile("testdata/pki/server-rsa.key"));
    defer rsa.deinit(testing.allocator);

    for (legacy_cases) |case| {
        const options: config.Server = .{
            .io = testing.io,
            .gpa = testing.allocator,
            .auth = if (std.mem.eql(u8, case.cert, "server-ec")) &ec else &rsa,
        };
        const result = try sClientOnce(io, options, &.{ case.flag, "-cipher", case.cipher, "-verify_return_error" });
        try result.outcome.handshake;
        try result.outcome.echo;
        try testing.expect(result.echoed);
        try testing.expectEqual(case.version, result.outcome.version.?);
        try testing.expectEqual(case.suite, result.outcome.suite.?);
    }
}

test "the libssl server: version ranges, suite lists, client certificates and SHA-1" {
    if (!libssl_build) return error.SkipZigTest;
    const io = testing.io;
    _ = try requireOpenSsl(io);
    var trust = try ztls.TrustStore.init();
    defer trust.deinit();
    try trust.addPem(testing.allocator, @embedFile("testdata/pki/ca.pem"));
    var rsa = try ztls.CertKeyPair.fromSlice(testing.allocator, @embedFile("testdata/pki/server-rsa.pem"), @embedFile("testdata/pki/server-rsa.key"));
    defer rsa.deinit(testing.allocator);
    const base: config.Server = .{ .io = testing.io, .gpa = testing.allocator, .auth = &rsa };

    // Held to TLS 1.2 at most, against a client that offers 1.3 too.
    var capped = base;
    capped.max_version = .tls_1_2;
    var result = try sClientOnce(io, capped, &.{});
    try result.outcome.handshake;
    try testing.expectEqual(proto.Version.tls_1_2, result.outcome.version.?);

    // Held to TLS 1.2 at least, against a TLS 1.1 client.
    var floor = base;
    floor.min_version = .tls_1_2;
    result = try sClientOnce(io, floor, &.{ "-tls1_1", "-cipher", "ECDHE-RSA-AES128-SHA:@SECLEVEL=0" });
    try testing.expectError(error.TlsProtocolVersion, result.outcome.handshake);

    // A list with one legacy suite is followed strictly.
    var listed = base;
    listed.cipher_suites = &.{ .aes_128_gcm_sha256, @enumFromInt(0x002f) };
    result = try sClientOnce(io, listed, &.{"-tls1_2"});
    try result.outcome.handshake;
    try testing.expectEqual(@as(proto.CipherSuite, @enumFromInt(0x002f)), result.outcome.suite.?);
    result = try sClientOnce(io, listed, &.{ "-tls1_2", "-cipher", "ECDHE-RSA-AES128-GCM-SHA256" });
    try testing.expectError(error.TlsHandshakeFailure, result.outcome.handshake);

    // A client certificate over TLS 1.2.
    var auth = base;
    auth.client_auth = .{ .root_ca = &trust, .auth_type = .require };
    result = try sClientOnce(io, auth, &.{ "-tls1_2", "-cert", pki ++ "client.pem", "-key", pki ++ "client.key" });
    try result.outcome.handshake;
    try testing.expectEqual(ztls.crypto.sig.KeyType{ .ecdsa = .p256 }, result.outcome.peer_key_type.?);

    // A TLS 1.2 client that takes SHA-1 signatures only.
    result = try sClientOnce(io, base, &.{ "-tls1_2", "-sigalgs", "RSA+SHA1", "-cipher", "ECDHE-RSA-AES128-GCM-SHA256:@SECLEVEL=0" });
    try result.outcome.handshake;
    try testing.expect(result.echoed);
}

/// Signs as the key would, and counts.
const CountingSigner = struct {
    calls: usize = 0,

    fn sign(context: ?*anyopaque, key: *const config.PrivateKey, algorithm: ztls.crypto.sig.Algorithm, message: []const u8, out: []u8) anyerror![]u8 {
        const self: *CountingSigner = @ptrCast(@alignCast(context.?));
        self.calls += 1;
        return key.sign(algorithm, message, out);
    }
};

test "the libssl server picks a certificate older clients can use, and keeps a signer from RSA key exchange" {
    if (!libssl_build) return error.SkipZigTest;
    const io = testing.io;
    _ = try requireOpenSsl(io);
    var rsa = try ztls.CertKeyPair.fromSlice(testing.allocator, @embedFile("testdata/pki/server-rsa.pem"), @embedFile("testdata/pki/server-rsa.key"));
    defer rsa.deinit(testing.allocator);
    var ed = try ztls.CertKeyPair.fromSlice(testing.allocator, @embedFile("testdata/pki/server-ed25519.pem"), @embedFile("testdata/pki/server-ed25519.key"));
    defer ed.deinit(testing.allocator);
    var signed = try ztls.CertKeyPair.fromSlice(testing.allocator, @embedFile("testdata/pki/server-rsa.pem"), @embedFile("testdata/pki/server-rsa.key"));
    defer signed.deinit(testing.allocator);
    var signer: CountingSigner = .{};
    signed.signer = .{ .context = &signer, .sign = CountingSigner.sign };
    const tls11: []const []const u8 = &.{ "-tls1_1", "-cipher", "ECDHE-RSA-AES128-SHA:@SECLEVEL=0" };

    var ec = try ztls.CertKeyPair.fromSlice(testing.allocator, @embedFile("testdata/pki/server-ec.pem"), @embedFile("testdata/pki/server-ec.key"));
    defer ec.deinit(testing.allocator);

    // Before TLS 1.2: not the Ed25519 certificate, nor one with a signer,
    // nor an ECDSA one for a client that offers RSA suites only.
    var result = try sClientOnce(io, .{ .io = testing.io, .gpa = testing.allocator, .auth = null, .certificates = &.{ &ed, &signed, &ec, &rsa } }, tls11);
    try result.outcome.handshake;
    try testing.expectEqual(0, signer.calls);
    // So in TLS 1.2, for a client that takes ECDSA signatures.
    result = try sClientOnce(io, .{ .io = testing.io, .gpa = testing.allocator, .auth = null, .certificates = &.{ &ec, &rsa } }, &.{ "-tls1_2", "-cipher", "ECDHE-RSA-AES128-GCM-SHA256" });
    try result.outcome.handshake;
    try testing.expectEqual(proto.CipherSuite.ecdhe_rsa_with_aes_128_gcm_sha256, result.outcome.suite.?);

    // The application's choice, told what the client can verify.
    const Picker = struct {
        offered: []const *const ztls.CertKeyPair,
        fn pick(context: ?*anyopaque, hello: config.SelectCertificate.Hello) ?*const ztls.CertKeyPair {
            const self: *@This() = @ptrCast(@alignCast(context.?));
            for (self.offered) |pair| {
                if (hello.acceptsKey(pair.key.key_type)) return pair;
            }
            return null;
        }
    };
    var picker: Picker = .{ .offered = &.{ &ed, &ec, &rsa } };
    const picking: config.Server = .{ .io = testing.io, .gpa = testing.allocator, .auth = null, .select_certificate = .{ .context = &picker, .callback = Picker.pick } };
    result = try sClientOnce(io, picking, tls11);
    try result.outcome.handshake;
    // In TLS 1.2, PKCS#1 v1.5 signs too.
    result = try sClientOnce(io, picking, &.{ "-tls1_2", "-sigalgs", "RSA+SHA256" });
    try result.outcome.handshake;

    // A signer's certificate, to a client that offers RSA key exchange
    // first: ECDHE is chosen instead, and with nothing else, the
    // handshake fails.
    const signing: config.Server = .{ .io = testing.io, .gpa = testing.allocator, .auth = &signed };
    result = try sClientOnce(io, signing, &.{ "-tls1_2", "-cipher", "AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256" });
    try result.outcome.handshake;
    try testing.expectEqual(proto.CipherSuite.ecdhe_rsa_with_aes_128_gcm_sha256, result.outcome.suite.?);
    try testing.expectEqual(1, signer.calls);
    result = try sClientOnce(io, signing, &.{ "-tls1_2", "-cipher", "AES128-GCM-SHA256" });
    try testing.expectError(error.TlsHandshakeFailure, result.outcome.handshake);
}

const go_echo = "tests/go/echo/main.go";

test "our client against Go's crypto/tls, with X25519MLKEM768" {
    const io = testing.io;
    try requireGo(io);
    var trust = try ztls.TrustStore.init();
    defer trust.deinit();
    try trust.addPem(testing.allocator, @embedFile("testdata/pki/ca.pem"));
    var client_pair = try ztls.CertKeyPair.fromSlice(testing.allocator, @embedFile("testdata/pki/client.pem"), @embedFile("testdata/pki/client.key"));
    defer client_pair.deinit(testing.allocator);

    const Case = struct {
        groups: []const proto.NamedGroup,
        client_cert: bool = false,
        transfer: usize = 0,
        tls12: bool = false,
    };
    const cases = [_]Case{
        // TLS 1.2 needs the leaf's curve, P-256, among the groups offered.
        .{ .groups = &.{ .x25519_ml_kem768, .x25519, .secp256r1 }, .tls12 = true },
        .{ .groups = &.{ .x25519, .secp256r1 }, .tls12 = true, .client_cert = true },
        .{ .groups = &.{.x25519_ml_kem768} },
        .{ .groups = &.{.x25519}, .client_cert = true },
        .{ .groups = &.{.secp256r1}, .transfer = 1 << 20 },
    };
    for (cases) |case| {
        var argv: std.ArrayList([]const u8) = .empty;
        defer argv.deinit(testing.allocator);
        try argv.appendSlice(testing.allocator, &.{
            "go",                   "run",
            go_echo,                "-listen",
            "127.0.0.1:0",          "-cert",
            pki ++ "server-ec.pem", "-key",
            pki ++ "server-ec.key", "-alpn",
            "h2,http/1.1",
        });
        if (case.client_cert) try argv.appendSlice(testing.allocator, &.{ "-require-client-cert", "-ca", pki ++ "ca.pem" });
        if (case.tls12) try argv.append(testing.allocator, "-tls12");
        const peer = try Peer.spawn(io, argv.items, .ignore, .pipe);
        // Until `finish`, which frees the peer whether or not it fails.
        var peer_running = true;
        errdefer if (peer_running) peer.abort();
        var line_buf: [128]u8 = undefined;
        const ready = try firstLine(peer, &line_buf);
        if (!std.mem.startsWith(u8, ready, "READY ")) return error.PeerNotReady;
        const port = try std.fmt.parseInt(u16, ready[std.mem.lastIndexOfScalar(u8, ready, ':').? + 1 ..], 10);

        var t: Transport = .{ .io = io, .stream = try connectWhenListening(io, port) };
        defer t.stream.close(io);
        t.setUp();
        var conn = try ztls.client(&t.input.interface, &t.output.interface, .{
            .io = testing.io,
            .gpa = testing.allocator,
            .host = "localhost",
            .root_ca = &trust,
            .named_groups = case.groups,
            .key_shares = case.groups,
            .alpn_protocols = &.{"h2"},
            .auth = if (case.client_cert) &client_pair else null,
            .cipher_suites = if (case.tls12) &(proto.CipherSuite.all ++ proto.CipherSuite.tls12) else &proto.CipherSuite.all,
        });
        defer conn.deinit();
        try testing.expectEqualStrings("h2", conn.alpn_protocol.?);

        var rbuf: [256]u8 = undefined;
        var r = conn.reader(&rbuf);
        var wbuf: [1024]u8 = undefined;
        var w = writerOf(&conn, &wbuf);
        try w.interface.writeAll("hello go\n");
        try w.interface.flush();
        try testing.expectEqualStrings("echo: hello go", (try r.interface.takeDelimiter('\n')).?);
        if (case.transfer > 0) {
            var sender = try io.concurrent(writePattern, .{ &w.interface, case.transfer });
            defer sender.cancel(io) catch {};
            try expectPattern(&r.interface, case.transfer, .echo);
            try sender.await(io);
        }
        try conn.close();
        try testing.expectEqual(null, try r.interface.takeDelimiter('\n'));
        peer_running = false;
        try peer.finish();
    }
}

test "Go's crypto/tls against our server, with X25519MLKEM768" {
    const io = testing.io;
    try requireGo(io);
    var trust = try ztls.TrustStore.init();
    defer trust.deinit();
    try trust.addPem(testing.allocator, @embedFile("testdata/pki/ca.pem"));
    var ec = try ztls.CertKeyPair.fromSlice(testing.allocator, @embedFile("testdata/pki/server-ec.pem"), @embedFile("testdata/pki/server-ec.key"));
    defer ec.deinit(testing.allocator);

    const Case = struct {
        groups: []const proto.NamedGroup,
        client_cert: bool = false,
        transfer: usize = 0,
    };
    const cases = [_]Case{
        .{ .groups = &.{.x25519_ml_kem768} },
        .{ .groups = &.{.x25519}, .client_cert = true },
        .{ .groups = &.{.secp256r1}, .transfer = 1 << 20 }, // Go shares X25519MLKEM768 and X25519 first: a retry
    };
    for (cases) |case| {
        var loopback = try testu.Loopback.init(io);
        defer loopback.deinit();
        var outcome: Outcome = .{};
        const options: config.Server = .{
            .io = testing.io,
            .gpa = testing.allocator,
            .auth = &ec,
            .alpn_protocols = &.{"h2"},
            .named_groups = case.groups,
            .client_auth = if (case.client_cert) .{ .root_ca = &trust, .auth_type = .require } else null,
        };
        var task = try io.concurrent(serveOnce, .{ &loopback, options, &outcome });
        defer task.cancel(io) catch {};

        var port_buf: [32]u8 = undefined;
        const connect = try std.fmt.bufPrint(&port_buf, "127.0.0.1:{d}", .{loopback.server.socket.address.getPort()});
        var argv: std.ArrayList([]const u8) = .empty;
        defer argv.deinit(testing.allocator);
        try argv.appendSlice(testing.allocator, &.{ "go", "run", go_echo, "-connect", connect, "-ca", pki ++ "ca.pem", "-alpn", "h2" });
        if (case.client_cert) try argv.appendSlice(testing.allocator, &.{ "-cert", pki ++ "client.pem", "-key", pki ++ "client.key" });
        const peer = try Peer.spawn(io, argv.items, .pipe, .pipe);
        // Until `finish`, which frees the peer whether or not it fails.
        var peer_running = true;
        errdefer if (peer_running) peer.abort();
        var wbuf: [1024]u8 = undefined;
        var stdin = peer.child.stdin.?.writer(io, &wbuf);
        var rbuf: [1024]u8 = undefined;
        var stdout = peer.child.stdout.?.reader(io, &rbuf);

        try testing.expectEqualStrings("ALPN h2", (try stdout.interface.takeDelimiter('\n')).?);
        try stdin.interface.writeAll("hello ztls\n");
        try stdin.interface.flush();
        try testing.expectEqualStrings("echo: hello ztls", (try stdout.interface.takeDelimiter('\n')).?);
        if (case.transfer > 0) {
            var sender = try io.concurrent(writePattern, .{ &stdin.interface, case.transfer });
            defer sender.cancel(io) catch {};
            try expectPattern(&stdout.interface, case.transfer, .echo);
            try sender.await(io);
        }
        peer.child.stdin.?.close(io);
        peer.child.stdin = null;
        try testing.expectEqual(null, try stdout.interface.takeDelimiter('\n'));
        peer_running = false;
        try peer.finish();

        try task.await(io);
        try outcome.handshake;
        try outcome.echo;
        try testing.expectEqualStrings("h2", outcome.alpn.?);
        if (case.client_cert) try testing.expectEqual(ztls.crypto.sig.KeyType{ .ecdsa = .p256 }, outcome.peer_key_type.?);
    }
}
