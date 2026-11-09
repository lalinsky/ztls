//! One connection to a public server with ztls, for the TLS 1.3 survey in
//! this directory. Usage: survey-probe HOST [PORT] [--groups a,b,...]
//! [--tls12].
//! Prints tab-separated fields: HOST ok SUITE GROUP RETRIED KEY SCHEME
//! ALPN STATUS, first with STATUS "-" as soon as the handshake is done and
//! again with the HTTP status line, or with "error: NAME" when the request
//! failed; or HOST fail ERROR when the handshake did.
//! --groups replaces the client's default groups, the first one getting
//! the key share. --tls12 offers TLS 1.2 after TLS 1.3; the suite shows
//! which was agreed.

const std = @import("std");
const ztls = @import("ztls");

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    var out_buf: [4096]u8 = undefined;
    var stdout = std.Io.File.stdout().writer(io, &out_buf);
    const out = &stdout.interface;
    defer out.flush() catch {};
    var host: ?[]const u8 = null;
    var port: u16 = 443;
    var groups: std.ArrayList(ztls.protocol.NamedGroup) = .empty;
    var tls12 = false;
    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        if (std.mem.eql(u8, args[i], "--tls12")) {
            tls12 = true;
        } else if (std.mem.eql(u8, args[i], "--groups") and i + 1 < args.len) {
            i += 1;
            var names = std.mem.splitScalar(u8, args[i], ',');
            while (names.next()) |name| {
                const group = std.meta.stringToEnum(ztls.protocol.NamedGroup, name) orelse return usage(out);
                try groups.append(init.arena.allocator(), group);
            }
        } else if (std.fmt.parseInt(u16, args[i], 10)) |p| {
            port = p;
        } else |_| {
            if (host != null) return usage(out);
            host = args[i];
        }
    }
    const name = host orelse return usage(out);
    probe(init.gpa, io, name, port, groups.items, tls12, out) catch |err| {
        try out.print("{s}\tfail\t{t}\n", .{ name, err });
    };
}

fn usage(out: *std.Io.Writer) !void {
    try out.writeAll("usage: survey-probe HOST [PORT] [--groups a,b,...] [--tls12]\n");
    std.process.exit(2);
}

fn probe(gpa: std.mem.Allocator, io: std.Io, host: []const u8, port: u16, groups: []const ztls.protocol.NamedGroup, tls12: bool, out: *std.Io.Writer) !void {
    var trust = try ztls.TrustStore.init();
    defer trust.deinit();
    try trust.addSystemBundle(gpa, io);

    const name = try std.Io.net.HostName.init(host);
    const stream = try name.connect(io, port, .{ .mode = .stream });
    defer stream.close(io);
    var input_buffer: [ztls.input_buffer_len]u8 = undefined;
    var output_buffer: [ztls.output_buffer_len]u8 = undefined;
    var input = stream.reader(io, &input_buffer);
    var output = stream.writer(io, &output_buffer);

    var options: ztls.config.Client = .{
        .allocator = gpa,
        .host = host,
        .root_ca = &trust,
        .alpn_protocols = &.{"http/1.1"},
        .now = std.Io.Clock.real.now(io),
    };
    const both = ztls.protocol.CipherSuite.all ++ ztls.protocol.CipherSuite.tls12;
    if (tls12) options.cipher_suites = &both;
    if (groups.len > 0) {
        options.named_groups = groups;
        options.key_shares = groups[0..1];
    }
    var conn = try ztls.client(&input.interface, &output.interface, options);
    defer conn.deinit();
    try report(out, host, &conn, "-");
    try out.flush();

    // TLS is done; whatever happens now is the HTTP server's doing.
    var status_buf: [128]u8 = undefined;
    const status = request(&conn, host) catch |err| try std.fmt.bufPrint(&status_buf, "error: {t}", .{err});
    try report(out, host, &conn, status);
    conn.close() catch {};
}

fn request(conn: *ztls.Connection, host: []const u8) ![]const u8 {
    var read_buffer: [8192]u8 = undefined;
    var reader = conn.reader(&read_buffer);
    var writer = conn.inPlaceWriter();
    try writer.interface.print("HEAD / HTTP/1.1\r\nHost: {s}\r\nUser-Agent: ztls-survey\r\nConnection: close\r\n\r\n", .{host});
    try writer.interface.flush();
    const line = reader.interface.takeDelimiter('\n') catch |err| return reader.err orelse err;
    return std.mem.trim(u8, line orelse return error.EmptyResponse, "\r");
}

fn report(out: *std.Io.Writer, host: []const u8, conn: *const ztls.Connection, status: []const u8) !void {
    try out.print("{s}\tok\t{s}\t{s}\t{s}\t{s}\t{s}\t{s}\t{s}\n", .{
        host,
        tagName(ztls.protocol.CipherSuite, conn.suite),
        tagName(ztls.protocol.NamedGroup, conn.group),
        if (conn.retried) "hrr" else "-",
        if (conn.peer_key_type) |key| @tagName(key) else "-",
        tagName(ztls.protocol.SignatureScheme, conn.peer_signature_scheme),
        conn.alpn_protocol orelse "-",
        status,
    });
}

fn tagName(comptime E: type, value: ?E) []const u8 {
    return std.enums.tagName(E, value orelse return "-") orelse "?";
}
