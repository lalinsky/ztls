//! The server tlsfuzzer's scripts connect to; see run.sh beside this file.
//! Each port is one setup, and every connection gets a thread of its own:
//!
//!   4433  RSA certificate. Reads until "\r\n\r\n", answers with an HTTP
//!         200 and closes. A request that mentions "keyupdate" gets a
//!         KeyUpdate asking the client to update too, ahead of the answer.
//!   4434  The same, asking for a client certificate (signed by the test
//!         CA) without requiring one.
//!   4435  RSA certificate, echoes whatever it reads.
//!   4436  ECDSA P-256 certificate, otherwise as 4433.
//!   4437  Ed25519 certificate, otherwise as 4433.
//!   4438  ECDSA P-384 certificate under an intermediate, otherwise as 4433.
//!
//! Run from the repository root; errors go to stderr, one line each.

const std = @import("std");
const ztls = @import("ztls");
const Io = std.Io;

const pki = "src/testdata/pki/";

const Mode = enum { http, echo };

const Listener = struct {
    port: u16,
    mode: Mode,
    options: ztls.config.Server,
};

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    const gpa = init.gpa;
    const cwd = Io.Dir.cwd();

    var rsa = try ztls.CertKeyPair.fromFilePath(gpa, io, cwd, pki ++ "server-rsa.pem", pki ++ "server-rsa.key");
    defer rsa.deinit(gpa);
    var ec = try ztls.CertKeyPair.fromFilePath(gpa, io, cwd, pki ++ "server-ec.pem", pki ++ "server-ec.key");
    defer ec.deinit(gpa);
    var ed25519 = try ztls.CertKeyPair.fromFilePath(gpa, io, cwd, pki ++ "server-ed25519.pem", pki ++ "server-ed25519.key");
    defer ed25519.deinit(gpa);
    var p384 = try ztls.CertKeyPair.fromFilePath(gpa, io, cwd, pki ++ "server-chain.pem", pki ++ "server-chain.key");
    defer p384.deinit(gpa);

    var ca = try ztls.TrustStore.init();
    defer ca.deinit();
    try ca.addPemFile(gpa, io, cwd, pki ++ "ca.pem");

    const now = Io.Clock.real.now(io);
    const listeners = [_]Listener{
        .{ .port = 4433, .mode = .http, .options = .{ .allocator = gpa, .auth = &rsa, .now = now } },
        .{ .port = 4434, .mode = .http, .options = .{
            .allocator = gpa,
            .auth = &rsa,
            .client_auth = .{ .root_ca = &ca, .auth_type = .request },
            .now = now,
        } },
        .{ .port = 4435, .mode = .echo, .options = .{ .allocator = gpa, .auth = &rsa, .now = now } },
        .{ .port = 4436, .mode = .http, .options = .{ .allocator = gpa, .auth = &ec, .now = now } },
        .{ .port = 4437, .mode = .http, .options = .{ .allocator = gpa, .auth = &ed25519, .now = now } },
        .{ .port = 4438, .mode = .http, .options = .{ .allocator = gpa, .auth = &p384, .now = now } },
    };

    var servers: [listeners.len]Io.net.Server = undefined;
    for (&servers, &listeners) |*server, *l| {
        const address = try Io.net.IpAddress.parse("127.0.0.1", l.port);
        server.* = try address.listen(io, .{ .reuse_address = true });
    }
    var group: Io.Group = .init;
    defer group.cancel(io);
    for (&servers, &listeners) |*server, *l| {
        try group.concurrent(io, acceptLoop, .{ io, &group, server, l });
    }
    std.debug.print("listening\n", .{});
    try group.await(io);
}

fn acceptLoop(io: Io, group: *Io.Group, server: *Io.net.Server, l: *const Listener) Io.Cancelable!void {
    while (true) {
        const stream = server.accept(io) catch |err| switch (err) {
            error.Canceled => return error.Canceled,
            else => {
                std.debug.print("{d}: accept: {t}\n", .{ l.port, err });
                continue;
            },
        };
        group.concurrent(io, serve, .{ io, stream, l }) catch |err| {
            std.debug.print("{d}: concurrent: {t}\n", .{ l.port, err });
            stream.close(io);
        };
    }
}

fn serve(io: Io, stream: Io.net.Stream, l: *const Listener) void {
    defer stream.close(io);
    var input_buffer: [ztls.input_buffer_len]u8 = undefined;
    var output_buffer: [ztls.output_buffer_len]u8 = undefined;
    var input = stream.reader(io, &input_buffer);
    var output = stream.writer(io, &output_buffer);
    // Read what the client still sends until it hangs up, so that closing
    // with unread input does not reset the connection and lose the alert
    // or close_notify just sent.
    defer {
        stream.shutdown(io, .send) catch {};
        _ = input.interface.discardRemaining() catch {};
    }

    var conn = ztls.server(&input.interface, &output.interface, l.options) catch |err| {
        std.debug.print("{d}: handshake: {t}\n", .{ l.port, err });
        return;
    };
    defer conn.deinit();

    const result = switch (l.mode) {
        .http => http(&conn),
        .echo => echo(&conn),
    };
    result catch |err| std.debug.print("{d}: {t}\n", .{ l.port, err });
    // Sends close_notify, or the alert for what the read side found.
    conn.close() catch {};
}

const http_ok = "HTTP/1.1 200 OK\r\nContent-Length: 12\r\nContent-Type: text/plain\r\n\r\nHello World!";

fn http(conn: *ztls.Connection) !void {
    var read_buffer: [16 * 1024]u8 = undefined;
    var r = conn.reader(&read_buffer);
    // The last bytes read, to find "\r\n\r\n" and "keyupdate" across records.
    var tail: [9]u8 = @splat(0);
    var key_update = false;
    read: while (true) {
        const chunk = r.interface.peekGreedy(1) catch |err| switch (err) {
            error.EndOfStream => return,
            error.ReadFailed => return r.err.?,
        };
        for (chunk, 1..) |byte, i| {
            std.mem.copyForwards(u8, tail[0 .. tail.len - 1], tail[1..]);
            tail[tail.len - 1] = byte;
            if (std.mem.eql(u8, &tail, "keyupdate")) key_update = true;
            if (std.mem.endsWith(u8, &tail, "\r\n\r\n")) {
                r.interface.toss(i);
                break :read;
            }
        }
        r.interface.toss(chunk.len);
    }
    if (key_update) try conn.requestKeyUpdate();
    var write_buffer: [1024]u8 = undefined;
    var w = conn.writer(&write_buffer);
    w.interface.writeAll(http_ok) catch return w.err.?;
    w.interface.flush() catch return w.err.?;
}

fn echo(conn: *ztls.Connection) !void {
    var read_buffer: [16 * 1024]u8 = undefined;
    var r = conn.reader(&read_buffer);
    var write_buffer: [16 * 1024]u8 = undefined;
    var w = conn.writer(&write_buffer);
    while (true) {
        const chunk = r.interface.peekGreedy(1) catch |err| switch (err) {
            error.EndOfStream => return,
            error.ReadFailed => return r.err.?,
        };
        w.interface.writeAll(chunk) catch return w.err.?;
        w.interface.flush() catch return w.err.?;
        r.interface.toss(chunk.len);
    }
}
