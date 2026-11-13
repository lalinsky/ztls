//! The shim BoringSSL's test runner (BoGo) drives. The runner starts one
//! shim per test with flags describing the role, the material and what
//! it expects, listens on a port, and the shim connects, writes its id,
//! runs the handshake and then echoes application data back with every
//! byte inverted. Exit 0 is success, 1 is failure with the reason on
//! stderr for the runner's error matching, and 89 says the flags ask for
//! something this shim does not implement.
//!
//! TLS 1.3 over TCP, and a TLS 1.2 client, are implemented; `config.json`
//! beside this file disables the tests that need more.

const std = @import("std");
const ztls = @import("ztls");

const exit_unimplemented = 89;

const Options = struct {
    port: u16 = 0,
    shim_id: u64 = 0,
    ipv6: bool = false,
    server: bool = false,
    cert_file: ?[]const u8 = null,
    key_file: ?[]const u8 = null,
    trust_cert: ?[]const u8 = null,
    verify_peer: bool = false,
    /// Verification must fail: an empty trust store sees to that.
    verify_fail: bool = false,
    require_any_client_certificate: bool = false,
    host_name: ?[]const u8 = null,
    advertise_alpn: ?[]const u8 = null,
    select_alpn: ?[]const u8 = null,
    decline_alpn: bool = false,
    expect_alpn: ?[]const u8 = null,
    expect_no_alpn: bool = false,
    expect_server_name: ?[]const u8 = null,
    expect_no_server_name: bool = false,
    expect_version: u16 = 0,
    expect_cipher: u16 = 0,
    expect_curve_id: u16 = 0,
    expect_peer_signature_algorithm: u16 = 0,
    expect_hrr: bool = false,
    expect_no_hrr: bool = false,
    expect_peer_cert_file: ?[]const u8 = null,
    expect_no_peer_cert: bool = false,
    curves: std.ArrayList(u16) = .empty,
    key_shares: ?std.ArrayList(u16) = null,
    tls13_ciphers: std.ArrayList(u16) = .empty,
    signing_prefs: std.ArrayList(u16) = .empty,
    verify_prefs: std.ArrayList(u16) = .empty,
    min_version: u16 = 0,
    max_version: u16 = 0,
    no_tls12: bool = false,
    no_tls13: bool = false,
    /// OpenSSL-style TLS 1.2 suite names, colon-separated.
    cipher: ?[]const u8 = null,
    read_size: usize = 512,
    shim_writes_first: bool = false,
    shim_initial_write: []const u8 = "hello",
    repeat_shim_initial_write: usize = 1,
    shim_shuts_down: bool = false,
    check_close_notify: bool = false,
    key_update: bool = false,
    key_update_before_read: bool = false,
    async: bool = false,
};

fn unimplemented(comptime fmt: []const u8, args: anytype) noreturn {
    std.debug.print("unimplemented: " ++ fmt ++ "\n", args);
    if (log_file) |file| {
        if (drain_io) |io| {
            var buf: [512]u8 = undefined;
            var w = file.writer(io, &buf);
            if (file.length(io)) |end| w.seekTo(end) catch {} else |_| {}
            w.interface.print("UNIMPLEMENTED: " ++ fmt ++ "\n", args) catch {};
            w.interface.flush() catch {};
        }
    }
    std.process.exit(exit_unimplemented);
}

var log_file: ?std.Io.File = null;

/// With ZTLS_BOGO_LOG set, every invocation appends its arguments there,
/// which is the only way to see what a test asked for.
fn logInvocation(io: std.Io, environ: *std.process.Environ.Map, args: []const [:0]const u8) void {
    const path = environ.get("ZTLS_BOGO_LOG") orelse return;
    const file = std.Io.Dir.cwd().openFile(io, path, .{ .mode = .write_only }) catch return;
    log_file = file;
    const end = file.length(io) catch return;
    var buf: [4096]u8 = undefined;
    var w = file.writer(io, &buf);
    w.seekTo(end) catch return;
    for (args[1..]) |arg| {
        w.interface.writeAll(arg) catch return;
        w.interface.writeAll(" ") catch return;
    }
    w.interface.writeAll("\n") catch return;
    w.interface.flush() catch return;
}

/// Set once connected: on exit the socket is half-closed and drained, as
/// the reference shim does, so the runner sees an end of stream rather
/// than a reset when it still has bytes in flight.
var drain_stream: ?std.Io.net.Stream = null;
var drain_io: ?std.Io = null;

fn drainAndExit(code: u8) noreturn {
    if (drain_stream) |stream| {
        if (drain_io) |io| {
            stream.shutdown(io, .send) catch {};
            var buf: [4096]u8 = undefined;
            var r = stream.reader(io, &buf);
            while (true) {
                const n = r.interface.readSliceShort(&buf) catch break;
                if (n == 0) break;
            }
        }
    }
    std.process.exit(code);
}

fn fail(comptime fmt: []const u8, args: anytype) noreturn {
    std.debug.print(fmt ++ "\n", args);
    drainAndExit(1);
}

fn parseArgs(gpa: std.mem.Allocator, args: []const [:0]const u8) !Options {
    var o: Options = .{};
    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        const arg = args[i];
        const Kind = enum { bool_flag, string, int, int_list, optional_int_list };
        const Flag = struct { name: []const u8, kind: Kind, field: []const u8 };
        const known = [_]Flag{
            .{ .name = "-port", .kind = .int, .field = "port" },
            .{ .name = "-shim-id", .kind = .int, .field = "shim_id" },
            .{ .name = "-ipv6", .kind = .bool_flag, .field = "ipv6" },
            .{ .name = "-server", .kind = .bool_flag, .field = "server" },
            .{ .name = "-cert-file", .kind = .string, .field = "cert_file" },
            .{ .name = "-key-file", .kind = .string, .field = "key_file" },
            .{ .name = "-trust-cert", .kind = .string, .field = "trust_cert" },
            .{ .name = "-verify-peer", .kind = .bool_flag, .field = "verify_peer" },
            .{ .name = "-verify-fail", .kind = .bool_flag, .field = "verify_fail" },
            .{ .name = "-require-any-client-certificate", .kind = .bool_flag, .field = "require_any_client_certificate" },
            .{ .name = "-host-name", .kind = .string, .field = "host_name" },
            .{ .name = "-advertise-alpn", .kind = .string, .field = "advertise_alpn" },
            .{ .name = "-select-alpn", .kind = .string, .field = "select_alpn" },
            .{ .name = "-decline-alpn", .kind = .bool_flag, .field = "decline_alpn" },
            .{ .name = "-expect-alpn", .kind = .string, .field = "expect_alpn" },
            .{ .name = "-expect-no-alpn", .kind = .bool_flag, .field = "expect_no_alpn" },
            .{ .name = "-expect-server-name", .kind = .string, .field = "expect_server_name" },
            .{ .name = "-expect-no-server-name", .kind = .bool_flag, .field = "expect_no_server_name" },
            .{ .name = "-expect-version", .kind = .int, .field = "expect_version" },
            .{ .name = "-expect-cipher", .kind = .int, .field = "expect_cipher" },
            .{ .name = "-expect-curve-id", .kind = .int, .field = "expect_curve_id" },
            .{ .name = "-expect-peer-signature-algorithm", .kind = .int, .field = "expect_peer_signature_algorithm" },
            .{ .name = "-expect-hrr", .kind = .bool_flag, .field = "expect_hrr" },
            .{ .name = "-expect-no-hrr", .kind = .bool_flag, .field = "expect_no_hrr" },
            .{ .name = "-expect-peer-cert-file", .kind = .string, .field = "expect_peer_cert_file" },
            .{ .name = "-expect-no-peer-cert", .kind = .bool_flag, .field = "expect_no_peer_cert" },
            .{ .name = "-curves", .kind = .int_list, .field = "curves" },
            .{ .name = "-key-shares", .kind = .optional_int_list, .field = "key_shares" },
            .{ .name = "-tls13-ciphers", .kind = .int_list, .field = "tls13_ciphers" },
            .{ .name = "-signing-prefs", .kind = .int_list, .field = "signing_prefs" },
            .{ .name = "-verify-prefs", .kind = .int_list, .field = "verify_prefs" },
            .{ .name = "-min-version", .kind = .int, .field = "min_version" },
            .{ .name = "-max-version", .kind = .int, .field = "max_version" },
            .{ .name = "-no-tls12", .kind = .bool_flag, .field = "no_tls12" },
            .{ .name = "-no-tls13", .kind = .bool_flag, .field = "no_tls13" },
            .{ .name = "-cipher", .kind = .string, .field = "cipher" },
            .{ .name = "-read-size", .kind = .int, .field = "read_size" },
            .{ .name = "-shim-writes-first", .kind = .bool_flag, .field = "shim_writes_first" },
            .{ .name = "-shim-initial-write", .kind = .string, .field = "shim_initial_write" },
            .{ .name = "-repeat-shim-initial-write", .kind = .int, .field = "repeat_shim_initial_write" },
            .{ .name = "-shim-shuts-down", .kind = .bool_flag, .field = "shim_shuts_down" },
            .{ .name = "-check-close-notify", .kind = .bool_flag, .field = "check_close_notify" },
            .{ .name = "-key-update", .kind = .bool_flag, .field = "key_update" },
            .{ .name = "-key-update-before-read", .kind = .bool_flag, .field = "key_update_before_read" },
            .{ .name = "-async", .kind = .bool_flag, .field = "async" },
        };
        // Accepted and ignored: they ask for nothing of a blocking
        // implementation, or are about versions it never offers.
        const ignored = [_][]const u8{
            "-no-tls1",            "-no-tls11",             "-enable-grease",
            "-permute-extensions", "-fuzzer-mode",          "-expect-ticket-renewal",
            // The handshake always runs first and whole here, and
            // certificates are configured up front, so these change nothing.
            "-implicit-handshake", "-handshake-never-done", "-use-old-client-cert-callback",
            "-use-early-callback",
            // No sessions are ever cached.
            "-expect-no-session-id", "-expect-session-miss",
            "-expect-no-session",
        };
        const ignored_with_value = [_][]const u8{ "-handshaker-path", "-expect-ticket-age-skew" };

        var handled = false;
        inline for (known) |flag| {
            if (std.mem.eql(u8, arg, flag.name)) {
                handled = true;
                switch (flag.kind) {
                    .bool_flag => @field(o, flag.field) = true,
                    .string => {
                        i += 1;
                        if (i >= args.len) fail("{s} needs a value", .{arg});
                        @field(o, flag.field) = args[i];
                    },
                    .int => {
                        i += 1;
                        if (i >= args.len) fail("{s} needs a value", .{arg});
                        const T = @TypeOf(@field(o, flag.field));
                        @field(o, flag.field) = std.fmt.parseInt(T, args[i], 10) catch fail("{s}: bad number {s}", .{ arg, args[i] });
                    },
                    .int_list => {
                        i += 1;
                        if (i >= args.len) fail("{s} needs a value", .{arg});
                        try @field(o, flag.field).append(gpa, std.fmt.parseInt(u16, args[i], 10) catch fail("{s}: bad number {s}", .{ arg, args[i] }));
                    },
                    .optional_int_list => {
                        i += 1;
                        if (i >= args.len) fail("{s} needs a value", .{arg});
                        if (@field(o, flag.field) == null) @field(o, flag.field) = .empty;
                        try @field(o, flag.field).?.append(gpa, std.fmt.parseInt(u16, args[i], 10) catch fail("{s}: bad number {s}", .{ arg, args[i] }));
                    },
                }
            }
        }
        if (handled) continue;
        for (ignored) |name| {
            if (std.mem.eql(u8, arg, name)) {
                handled = true;
                break;
            }
        }
        if (handled) continue;
        for (ignored_with_value) |name| {
            if (std.mem.eql(u8, arg, name)) {
                handled = true;
                i += 1;
                break;
            }
        }
        if (handled) continue;
        unimplemented("flag {s}", .{arg});
    }
    return o;
}

/// BoGo numbers groups, suites and schemes as the wire does. Only named
/// values count; the enums are non-exhaustive.
fn fromWire(comptime E: type, id: u16) ?E {
    for (std.enums.values(E)) |value| {
        if (@intFromEnum(value) == id) return value;
    }
    return null;
}

/// OpenSSL's names for the TLS 1.2 suites, as `-cipher` gives them.
fn suiteFromName(name: []const u8) ?ztls.protocol.CipherSuite {
    const names = [_]struct { []const u8, ztls.protocol.CipherSuite }{
        .{ "ECDHE-ECDSA-AES128-GCM-SHA256", .ecdhe_ecdsa_with_aes_128_gcm_sha256 },
        .{ "ECDHE-ECDSA-AES256-GCM-SHA384", .ecdhe_ecdsa_with_aes_256_gcm_sha384 },
        .{ "ECDHE-RSA-AES128-GCM-SHA256", .ecdhe_rsa_with_aes_128_gcm_sha256 },
        .{ "ECDHE-RSA-AES256-GCM-SHA384", .ecdhe_rsa_with_aes_256_gcm_sha384 },
        .{ "ECDHE-ECDSA-CHACHA20-POLY1305", .ecdhe_ecdsa_with_chacha20_poly1305_sha256 },
        .{ "ECDHE-RSA-CHACHA20-POLY1305", .ecdhe_rsa_with_chacha20_poly1305_sha256 },
    };
    for (names) |entry| {
        if (std.mem.eql(u8, name, entry[0])) return entry[1];
    }
    return null;
}

fn groupFromId(id: u16) ?ztls.protocol.NamedGroup {
    return fromWire(ztls.protocol.NamedGroup, id);
}

/// The schemes in `ids`, which must be ones ztls implements, each once.
fn schemesFromIds(arena: std.mem.Allocator, ids: []const u16) ![]const ztls.protocol.SignatureScheme {
    var schemes: std.ArrayList(ztls.protocol.SignatureScheme) = .empty;
    for (ids) |id| {
        const scheme = fromWire(ztls.protocol.SignatureScheme, id) orelse unimplemented("signature scheme {x}", .{id});
        if (std.mem.indexOfScalar(ztls.protocol.SignatureScheme, &ztls.config.default_signature_schemes, scheme) == null) unimplemented("signature scheme {x}", .{id});
        if (std.mem.indexOfScalar(ztls.protocol.SignatureScheme, schemes.items, scheme) != null) unimplemented("signature scheme {x} twice", .{id});
        try schemes.append(arena, scheme);
    }
    return schemes.items;
}

fn suiteFromId(id: u16) ?ztls.protocol.CipherSuite {
    return fromWire(ztls.protocol.CipherSuite, id);
}

/// `-advertise-alpn` is the extension's wire form: length-prefixed names.
fn parseAlpnWire(gpa: std.mem.Allocator, wire: []const u8) ![]const []const u8 {
    var list: std.ArrayList([]const u8) = .empty;
    var i: usize = 0;
    while (i < wire.len) {
        const len = wire[i];
        i += 1;
        if (i + len > wire.len) fail("bad -advertise-alpn", .{});
        try list.append(gpa, wire[i .. i + len]);
        i += len;
    }
    return list.toOwnedSlice(gpa);
}

fn readFile(gpa: std.mem.Allocator, io: std.Io, path: []const u8) ![]u8 {
    return std.Io.Dir.cwd().readFileAlloc(io, path, gpa, .limited(16 << 20));
}

pub fn main(init: std.process.Init) !void {
    const gpa = init.gpa;
    const io = init.io;
    drain_io = io;
    const arena = init.arena.allocator();
    const args = try init.minimal.args.toSlice(arena);
    logInvocation(io, init.environ_map, args);
    // The runner probes for BoringSSL's split handshaker before any test.
    for (args[1..]) |arg| {
        if (std.mem.eql(u8, arg, "-is-handshaker-supported")) {
            var buf: [8]u8 = undefined;
            var out = std.Io.File.stdout().writer(io, &buf);
            try out.interface.writeAll("No\n");
            try out.interface.flush();
            return;
        }
    }
    var o = try parseArgs(arena, args);

    // Versions: TLS 1.3 on both sides, TLS 1.2 for the client. Like
    // BoringSSL, all of them by default.
    const max_version: u16 = if (o.max_version == 0) 0x0304 else o.max_version;
    const min_version: u16 = if (o.min_version == 0) 0x0301 else o.min_version;
    const offer13 = !o.no_tls13 and min_version <= 0x0304 and max_version >= 0x0304;
    const offer12 = !o.no_tls12 and !o.server and min_version <= 0x0303 and max_version >= 0x0303;
    if (!offer13 and !offer12) unimplemented("versions {x} to {x}", .{ min_version, max_version });

    var named_groups: std.ArrayList(ztls.protocol.NamedGroup) = .empty;
    for (o.curves.items) |id| {
        try named_groups.append(arena, groupFromId(id) orelse unimplemented("group {d}", .{id}));
    }
    var key_shares: std.ArrayList(ztls.protocol.NamedGroup) = .empty;
    if (o.key_shares) |shares| {
        for (shares.items) |id| try key_shares.append(arena, groupFromId(id) orelse unimplemented("group {d}", .{id}));
    }
    var suites: std.ArrayList(ztls.protocol.CipherSuite) = .empty;
    if (offer13) {
        for (o.tls13_ciphers.items) |id| {
            try suites.append(arena, suiteFromId(id) orelse unimplemented("cipher suite {x}", .{id}));
        }
        if (o.tls13_ciphers.items.len == 0) try suites.appendSlice(arena, &ztls.protocol.CipherSuite.all);
    }
    if (offer12) {
        if (o.cipher) |names| {
            var it = std.mem.tokenizeScalar(u8, names, ':');
            while (it.next()) |name| try suites.append(arena, suiteFromName(name) orelse unimplemented("cipher {s}", .{name}));
        } else {
            try suites.appendSlice(arena, &ztls.protocol.CipherSuite.tls12);
        }
    }

    var trust = try ztls.TrustStore.init();
    defer trust.deinit();
    if (o.trust_cert) |path| if (path.len > 0 and !o.verify_fail) {
        const pem = try readFile(gpa, io, path);
        defer gpa.free(pem);
        try trust.addPem(gpa, pem);
    };

    var pair: ?ztls.CertKeyPair = null;
    defer if (pair) |*p| p.deinit(gpa);
    if (o.cert_file != null or o.key_file != null) {
        const cert_path = o.cert_file orelse fail("-cert-file without -key-file", .{});
        const key_path = o.key_file orelse fail("-key-file without -cert-file", .{});
        pair = ztls.CertKeyPair.fromFilePath(gpa, io, .cwd(), cert_path, key_path) catch |err| switch (err) {
            error.UnsupportedKey => unimplemented("key type in {s}", .{key_path}),
            else => fail("loading {s}: {s}", .{ key_path, @errorName(err) }),
        };
    }

    var alpn_protocols: []const []const u8 = &.{};
    if (o.server) {
        if (o.select_alpn) |p| alpn_protocols = &.{p};
    } else if (o.advertise_alpn) |wire| {
        alpn_protocols = try parseAlpnWire(arena, wire);
    }

    // Connect and identify ourselves.
    const address = try std.Io.net.IpAddress.parse(if (o.ipv6) "::1" else "127.0.0.1", o.port);
    const stream = try address.connect(io, .{ .mode = .stream });
    defer stream.close(io);
    drain_stream = stream;
    var input_buf: [ztls.input_buffer_len]u8 = undefined;
    var output_buf: [ztls.output_buffer_len]u8 = undefined;
    var tcp_reader = stream.reader(io, &input_buf);
    var tcp_writer = stream.writer(io, &output_buf);
    var id: [8]u8 = undefined;
    std.mem.writeInt(u64, &id, o.shim_id, .little);
    try tcp_writer.interface.writeAll(&id);
    try tcp_writer.interface.flush();

    const now = std.Io.Clock.real.now(io);
    var conn = (if (o.server) blk: {
        const auth = if (pair) |*p| p else fail("a server needs -cert-file and -key-file", .{});
        var options: ztls.config.Server = .{
            .io = io,
            .gpa = gpa,
            .auth = auth,
            .alpn_protocols = alpn_protocols,
            .now = now,
            .max_handshake_message_len = 1 << 20,
            .keep_peer_certificates = true,
        };
        if (suites.items.len > 0) options.cipher_suites = suites.items;
        if (named_groups.items.len > 0) options.named_groups = named_groups.items;
        if (o.signing_prefs.items.len > 0) options.signing_schemes = try schemesFromIds(arena, o.signing_prefs.items);
        if (o.verify_prefs.items.len > 0) options.verify_schemes = try schemesFromIds(arena, o.verify_prefs.items);
        if (o.require_any_client_certificate or o.verify_peer or o.verify_fail) {
            options.client_auth = .{ .root_ca = &trust, .auth_type = if (o.require_any_client_certificate) .require else .request };
        }
        break :blk ztls.server(&tcp_reader.interface, &tcp_writer.interface, options);
    } else blk: {
        var options: ztls.config.Client = .{
            .io = io,
            .gpa = gpa,
            .keep_peer_certificates = true,
            // No -host-name means no SNI, which an IP literal gives us.
            .host = o.host_name orelse "127.0.0.1",
            .root_ca = &trust,
            .insecure_skip_verify = !(o.verify_peer or o.verify_fail),
            .auth = if (pair) |*p| p else null,
            .alpn_protocols = alpn_protocols,
            .now = now,
            .max_handshake_message_len = 1 << 20,
            // BoringSSL's default list, which the runner's tests assume:
            // ztls's own default leaves P-384 out.
            .named_groups = &.{ .x25519_ml_kem768, .x25519, .secp256r1, .secp384r1 },
        };
        options.cipher_suites = suites.items;
        if (named_groups.items.len > 0) {
            options.named_groups = named_groups.items;
            if (o.key_shares == null) {
                // As BoringSSL: a share for the first group, and one for the
                // first group of the other kind (hybrid or classical).
                var shares: std.ArrayList(ztls.protocol.NamedGroup) = .empty;
                try shares.append(arena, named_groups.items[0]);
                const first_hybrid = named_groups.items[0] == .x25519_ml_kem768;
                for (named_groups.items[1..]) |g| {
                    if ((g == .x25519_ml_kem768) != first_hybrid) {
                        try shares.append(arena, g);
                        break;
                    }
                }
                options.key_shares = shares.items;
            }
        }
        if (o.key_shares != null) options.key_shares = key_shares.items;
        if (o.signing_prefs.items.len > 0) options.signing_schemes = try schemesFromIds(arena, o.signing_prefs.items);
        if (o.verify_prefs.items.len > 0) options.verify_schemes = try schemesFromIds(arena, o.verify_prefs.items);
        break :blk ztls.client(&tcp_reader.interface, &tcp_writer.interface, options);
    }) catch |err| switch (err) {
        error.ReadFailed => fail("handshake: transport read failed: {s}", .{@errorName(tcp_reader.err orelse error.Unknown)}),
        error.WriteFailed => fail("handshake: transport write failed: {s}", .{@errorName(tcp_writer.err orelse error.Unknown)}),
        // A server asked for a version it does not speak: a test with no
        // TLS 1.3 in it, which only its configuration knows.
        error.TlsAlertProtocolVersion, error.TlsProtocolVersion => if (o.server)
            unimplemented("TLS 1.3 was not negotiated: {s}", .{@errorName(err)})
        else
            fail("handshake failed: {s}", .{@errorName(err)}),
        else => fail("handshake failed: {s}", .{@errorName(err)}),
    };
    defer conn.deinit();
    conn.strict_close_notify = o.check_close_notify;

    try checkExpectations(gpa, io, &o, &conn);

    var read_buf: [16384]u8 = undefined;
    var reader = conn.reader(&read_buf);
    var writer = conn.writerInPlace();

    if (o.shim_writes_first) {
        for (0..o.repeat_shim_initial_write) |_| {
            writer.interface.writeAll(o.shim_initial_write) catch fail("initial write: {s}", .{@errorName(writer.err orelse error.WriteFailed)});
        }
        writer.interface.flush() catch fail("initial write: {s}", .{@errorName(writer.err orelse error.WriteFailed)});
    }

    if (!o.shim_shuts_down) {
        while (true) {
            if (o.key_update_before_read) writer.requestKeyUpdate() catch |err| fail("key update: {s}", .{@errorName(err)});
            // Whatever has arrived, up to the read size, like SSL_read.
            const avail = reader.interface.peekGreedy(1) catch |err| switch (err) {
                error.EndOfStream => break,
                error.ReadFailed => readFailed(&conn, &reader),
            };
            const n = @min(avail.len, o.read_size);
            if (o.key_update) writer.requestKeyUpdate() catch |err| fail("key update: {s}", .{@errorName(err)});
            for (avail[0..n]) |*b| b.* ^= 0xff;
            writer.interface.writeAll(avail[0..n]) catch fail("write: {s}", .{@errorName(writer.err orelse error.WriteFailed)});
            writer.interface.flush() catch fail("write: {s}", .{@errorName(writer.err orelse error.WriteFailed)});
            reader.interface.toss(n);
        }
    }

    conn.close() catch |err| fail("close: {s}", .{@errorName(err)});
    if (o.shim_shuts_down and o.check_close_notify) {
        var scratch: [64]u8 = undefined;
        const n = reader.interface.readSliceShort(&scratch) catch {
            if (reader.err) |e| if (e == error.TlsConnectionTruncated) fail("Unexpected SSL_shutdown result: -1 != 1", .{});
            readFailed(&conn, &reader);
        };
        if (n != 0) fail("data instead of close_notify", .{});
    }
    drainAndExit(0);
}

/// A read failed: the alert for it, if any, goes out with the next
/// write, so give the connection that chance before reporting.
fn readFailed(conn: *ztls.Connection, reader: *const ztls.Connection.Reader) noreturn {
    const err = reader.err orelse error.ReadFailed;
    conn.close() catch {};
    fail("read: {s}", .{@errorName(err)});
}

fn checkExpectations(gpa: std.mem.Allocator, io: std.Io, o: *const Options, conn: *const ztls.Connection) !void {
    if (o.expect_version != 0 and @intFromEnum(conn.version.?) != o.expect_version) {
        fail("Version was {x}, wanted {x}", .{ @intFromEnum(conn.version.?), o.expect_version });
    }
    if (o.expect_cipher != 0 and @intFromEnum(conn.suite.?) != o.expect_cipher) {
        fail("Cipher ID was {x}, wanted {x}", .{ @intFromEnum(conn.suite.?), o.expect_cipher });
    }
    if (o.expect_curve_id != 0 and @intFromEnum(conn.group.?) != o.expect_curve_id) {
        fail("curve_id was {x}, wanted {x}", .{ @intFromEnum(conn.group.?), o.expect_curve_id });
    }
    if (o.expect_peer_signature_algorithm != 0) {
        const got: u16 = if (conn.peer_signature_scheme) |s| @intFromEnum(s) else 0;
        if (got != o.expect_peer_signature_algorithm) fail("Peer signature algorithm was {x}, wanted {x}", .{ got, o.expect_peer_signature_algorithm });
    }
    if (o.expect_hrr and !conn.retried) fail("Got no HRR, but wanted one", .{});
    if (o.expect_no_hrr and conn.retried) fail("Got HRR, but wanted none", .{});

    const expected_alpn: ?[]const u8 = if (o.server) o.select_alpn else o.expect_alpn;
    if (expected_alpn) |want| {
        if (want.len > 0 or o.expect_no_alpn) {
            const got = conn.alpn_protocol orelse "";
            if (!std.mem.eql(u8, got, want)) fail("negotiated alpn proto mismatch: got {s}, want {s}", .{ got, want });
        }
    } else if (o.expect_no_alpn and conn.alpn_protocol != null) {
        fail("negotiated alpn proto, wanted none", .{});
    }

    if (o.expect_server_name) |want| {
        const got = conn.serverName() orelse fail("servername mismatch (got none; want {s})", .{want});
        if (!std.mem.eql(u8, got, want)) fail("servername mismatch (got {s}; want {s})", .{ got, want });
    }
    if (o.expect_no_server_name and conn.serverName() != null) fail("unexpected server name", .{});

    if (o.expect_no_peer_cert and conn.peer_certificates.len > 0) fail("Received unexpected peer certificate.", .{});
    if (!o.expect_no_peer_cert and (!o.server or o.require_any_client_certificate) and conn.peer_certificates.len == 0) {
        fail("Received no peer certificate but expected one.", .{});
    }
    if (o.expect_peer_cert_file) |path| {
        const pem = try readFile(gpa, io, path);
        defer gpa.free(pem);
        var it = ztls.crypto.pem.Iterator.init(pem);
        var i: usize = 0;
        while (try it.next()) |block| {
            if (!std.mem.eql(u8, block.label, "CERTIFICATE")) continue;
            const buf = try gpa.alloc(u8, block.decodedSizeUpperBound());
            defer gpa.free(buf);
            const der = try block.decode(buf);
            if (i >= conn.peer_certificates.len or !std.mem.eql(u8, der, conn.peer_certificates[i])) fail("peer certificate {d} did not match", .{i});
            i += 1;
        }
        if (i != conn.peer_certificates.len) fail("peer sent {d} certificates, wanted {d}", .{ conn.peer_certificates.len, i });
    }
}
