//! Helpers for tests.

const std = @import("std");

/// Bytes from hex, ignoring anything that is not a hex digit, so vectors can
/// be pasted from RFCs and hex viewers as they are.
pub fn hexToBytes(comptime hex: []const u8) [removeNonHex(hex).len / 2]u8 {
    @setEvalBranchQuota(1000 * 100);
    const clean = comptime removeNonHex(hex);
    comptime var res: [clean.len / 2]u8 = undefined;
    _ = comptime std.fmt.hexToBytes(&res, clean) catch unreachable;
    return res;
}

fn removeNonHex(comptime hex: []const u8) []const u8 {
    @setEvalBranchQuota(1000 * 100);
    var res: [hex.len]u8 = undefined;
    var i: usize = 0;
    for (hex) |ch| {
        if (std.ascii.isHex(ch)) {
            res[i] = ch;
            i += 1;
        }
    }
    const out = res[0..i].*;
    return &out;
}

test hexToBytes {
    const hex =
        \\e3b0c442 98fc1c14 9afbf4c8 996fb924
        \\27ae41e4 649b934c a495991b 7852b855
    ;
    try std.testing.expectEqual(
        [_]u8{
            0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
            0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
            0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
            0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
        },
        hexToBytes(hex),
    );
}

/// A TCP connection to ourselves over the loopback interface, for self-talk
/// tests. The two ends run as concurrent std.Io tasks, as they would in an
/// application, over the real socket reader and writer.
pub const Loopback = struct {
    io: std.Io,
    server: std.Io.net.Server,

    pub fn init(io: std.Io) !Loopback {
        const address = try std.Io.net.IpAddress.parse("127.0.0.1", 0);
        return .{ .io = io, .server = try address.listen(io, .{}) };
    }

    pub fn deinit(l: *Loopback) void {
        l.server.deinit(l.io);
    }

    pub fn connect(l: *const Loopback) !std.Io.net.Stream {
        return l.server.socket.address.connect(l.io, .{ .mode = .stream });
    }

    pub fn accept(l: *Loopback) !std.Io.net.Stream {
        return l.server.accept(l.io);
    }
};

test "Loopback connects two tasks" {
    const io = std.testing.io;
    var loopback = try Loopback.init(io);
    defer loopback.deinit();

    const Peer = struct {
        fn run(l: *Loopback) !void {
            const stream = try l.accept();
            defer stream.close(l.io);
            var buffer: [64]u8 = undefined;
            var writer = stream.writer(l.io, &buffer);
            for (0..100) |i| try writer.interface.print("line {d}\n", .{i});
            try writer.interface.flush();
        }
    };
    var peer = try io.concurrent(Peer.run, .{&loopback});
    defer peer.cancel(io) catch {};

    const stream = try loopback.connect();
    defer stream.close(io);
    var buffer: [64]u8 = undefined;
    var reader = stream.reader(io, &buffer);
    var count: usize = 0;
    while (try reader.interface.takeDelimiter('\n')) |line| {
        var expected: [32]u8 = undefined;
        try std.testing.expectEqualStrings(try std.fmt.bufPrint(&expected, "line {d}", .{count}), line);
        count += 1;
    }
    try peer.await(io);
    try std.testing.expectEqual(100, count);
}
