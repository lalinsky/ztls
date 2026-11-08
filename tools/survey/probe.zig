//! One connection to a public server with ztls, for the TLS 1.3 survey in
//! this directory. Usage: survey-probe HOST [PORT]. Prints one line of
//! tab-separated fields: HOST ok SUITE GROUP RETRIED KEY SCHEME ALPN STATUS,
//! or HOST fail ERROR.

const std = @import("std");
const ztls = @import("ztls");

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    var out_buf: [4096]u8 = undefined;
    var stdout = std.Io.File.stdout().writer(io, &out_buf);
    const out = &stdout.interface;
    defer out.flush() catch {};
    if (args.len < 2 or args.len > 3) {
        try out.writeAll("usage: survey-probe HOST [PORT]\n");
        std.process.exit(2);
    }
    const host = args[1];
    const port: u16 = if (args.len == 3) try std.fmt.parseInt(u16, args[2], 10) else 443;
    probe(init.gpa, io, host, port, out) catch |err| {
        try out.print("{s}\tfail\t{t}\n", .{ host, err });
    };
}

fn probe(gpa: std.mem.Allocator, io: std.Io, host: []const u8, port: u16, out: *std.Io.Writer) !void {
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

    var conn = try ztls.client(&input.interface, &output.interface, .{
        .allocator = gpa,
        .host = host,
        .root_ca = &trust,
        .alpn_protocols = &.{"http/1.1"},
        .now = std.Io.Clock.real.now(io),
    });
    defer conn.deinit();

    var read_buffer: [8192]u8 = undefined;
    var reader = conn.reader(&read_buffer);
    var writer = conn.inPlaceWriter();
    try writer.interface.print("HEAD / HTTP/1.1\r\nHost: {s}\r\nUser-Agent: ztls-survey\r\nConnection: close\r\n\r\n", .{host});
    try writer.interface.flush();
    const line = reader.interface.takeDelimiter('\n') catch |err| return reader.err orelse err;
    const status = std.mem.trim(u8, line orelse return error.EmptyResponse, "\r");

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
    conn.close() catch {};
}

fn tagName(comptime E: type, value: ?E) []const u8 {
    return std.enums.tagName(E, value orelse return "-") orelse "?";
}
