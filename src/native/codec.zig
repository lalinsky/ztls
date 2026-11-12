//! Reading and writing the TLS wire format: a bounded cursor over a
//! message, and a fixed-buffer builder with length prefixes patched in
//! afterwards.

const std = @import("std");
const assert = std.debug.assert;

/// A cursor over `bytes` that never reads past the end: every failure is
/// `TlsDecodeError`, and after one the decoder is spent (a failed `vector`
/// has consumed its length prefix), so a caller never retries another
/// shape.
pub const Decoder = struct {
    bytes: []const u8,
    pos: usize = 0,

    pub const Error = error{TlsDecodeError};

    pub fn init(bytes: []const u8) Decoder {
        return .{ .bytes = bytes };
    }

    pub fn rest(d: Decoder) []const u8 {
        return d.bytes[d.pos..];
    }

    pub fn remaining(d: Decoder) usize {
        return d.bytes.len - d.pos;
    }

    pub fn eof(d: Decoder) bool {
        return d.pos == d.bytes.len;
    }

    /// Fails unless everything has been consumed.
    pub fn expectEof(d: Decoder) Error!void {
        if (!d.eof()) return error.TlsDecodeError;
    }

    pub fn skip(d: *Decoder, n: usize) Error!void {
        if (n > d.remaining()) return error.TlsDecodeError;
        d.pos += n;
    }

    pub fn slice(d: *Decoder, n: usize) Error![]const u8 {
        try d.skip(n);
        return d.bytes[d.pos - n ..][0..n];
    }

    pub fn array(d: *Decoder, comptime n: usize) Error!*const [n]u8 {
        return (try d.slice(n))[0..n];
    }

    /// A big-endian integer of 8, 16, 24 or 32 bits, or a non-exhaustive
    /// enum of one.
    pub fn decode(d: *Decoder, comptime T: type) Error!T {
        switch (@typeInfo(T)) {
            .int => |info| {
                const n = comptime @divExact(info.bits, 8);
                return std.mem.readInt(T, try d.array(n), .big);
            },
            .@"enum" => |info| {
                comptime assert(!isExhaustive(info));
                return @enumFromInt(try d.decode(info.tag_type));
            },
            else => @compileError("cannot decode " ++ @typeName(T)),
        }
    }

    /// A vector with a length prefix of `Len` bits, as its own decoder.
    pub fn vector(d: *Decoder, comptime Len: type) Error!Decoder {
        const len = try d.decode(Len);
        return .init(try d.slice(len));
    }

    /// A vector with a length prefix of `Len` bits, as bytes.
    pub fn vectorBytes(d: *Decoder, comptime Len: type) Error![]const u8 {
        const len = try d.decode(Len);
        return d.slice(len);
    }
};

/// Writes into a fixed buffer. It fails when the buffer runs out, or when
/// a length prefix cannot hold what was written under it (a chain or a
/// list from the configuration that is too long for the wire).
pub const Writer = struct {
    buffer: []u8,
    end: usize = 0,

    pub const Error = error{ OutputBufferUndersize, LengthOverflow };

    pub fn init(buffer: []u8) Writer {
        return .{ .buffer = buffer };
    }

    pub fn written(w: Writer) []u8 {
        return w.buffer[0..w.end];
    }

    pub fn unused(w: Writer) []u8 {
        return w.buffer[w.end..];
    }

    pub fn ensure(w: Writer, n: usize) Error!void {
        if (n > w.buffer.len - w.end) return error.OutputBufferUndersize;
    }

    /// Claims the next `n` bytes for the caller to fill.
    pub fn writable(w: *Writer, n: usize) Error![]u8 {
        try w.ensure(n);
        w.end += n;
        return w.buffer[w.end - n ..][0..n];
    }

    pub fn writableArray(w: *Writer, comptime n: usize) Error!*[n]u8 {
        return (try w.writable(n))[0..n];
    }

    pub fn byte(w: *Writer, b: u8) Error!void {
        (try w.writable(1))[0] = b;
    }

    pub fn slice(w: *Writer, bytes: []const u8) Error!void {
        @memcpy(try w.writable(bytes.len), bytes);
    }

    pub fn int(w: *Writer, comptime T: type, value: anytype) Error!void {
        std.mem.writeInt(T, try w.writableArray(@divExact(@typeInfo(T).int.bits, 8)), @intCast(value), .big);
    }

    pub fn enumValue(w: *Writer, value: anytype) Error!void {
        const Tag = @typeInfo(@TypeOf(value)).@"enum".tag_type;
        try w.int(Tag, @intFromEnum(value));
    }

    /// A vector of 16-bit enum values with a 16-bit length prefix.
    pub fn enumList(w: *Writer, values: anytype) Error!void {
        const len = try w.beginLength(u16);
        for (values) |v| try w.enumValue(v);
        try len.end(w);
    }

    /// A vector of bytes with a length prefix of `Len` bits.
    pub fn vector(w: *Writer, comptime Len: type, bytes: []const u8) Error!void {
        if (bytes.len > std.math.maxInt(Len)) return error.LengthOverflow;
        try w.int(Len, bytes.len);
        try w.slice(bytes);
    }

    /// Where a length prefix goes, written by `end` once the contents are
    /// in place.
    pub fn Length(comptime Len: type) type {
        return struct {
            start: usize,

            pub fn end(self: @This(), w: *Writer) Error!void {
                const n = @divExact(@typeInfo(Len).int.bits, 8);
                const len = w.end - self.start - n;
                if (len > std.math.maxInt(Len)) return error.LengthOverflow;
                std.mem.writeInt(Len, w.buffer[self.start..][0..n], @intCast(len), .big);
            }
        };
    }

    pub fn beginLength(w: *Writer, comptime Len: type) Error!Length(Len) {
        const start = w.end;
        _ = try w.writable(@divExact(@typeInfo(Len).int.bits, 8));
        return .{ .start = start };
    }
};

fn isExhaustive(info: anytype) bool {
    // Zig 0.17 replaced `is_exhaustive` with `mode`.
    return if (@hasField(@TypeOf(info), "is_exhaustive")) info.is_exhaustive else info.mode == .exhaustive;
}

const testing = std.testing;
const proto = @import("../protocol.zig");
const data13 = @import("../testdata/tls13.zig");

test "decoding the example ServerHello" {
    const record = data13.server_hello;
    var d = Decoder.init(&record);
    try testing.expectEqual(proto.ContentType.handshake, try d.decode(proto.ContentType));
    try testing.expectEqual(proto.Version.tls_1_2, try d.decode(proto.Version));
    var body = try d.vector(u16);
    try d.expectEof();

    try testing.expectEqual(proto.HandshakeType.server_hello, try body.decode(proto.HandshakeType));
    var hello = try body.vector(u24);
    try body.expectEof();
    try testing.expectEqual(proto.Version.tls_1_2, try hello.decode(proto.Version));
    try testing.expectEqualSlices(u8, &data13.server_random, try hello.array(32));
    try testing.expectEqual(32, (try hello.vectorBytes(u8)).len); // session id
    try testing.expectEqual(proto.CipherSuite.aes_256_gcm_sha384, try hello.decode(proto.CipherSuite));
    try testing.expectEqual(0, try hello.decode(u8)); // compression
    var extensions = try hello.vector(u16);
    try hello.expectEof();

    try testing.expectEqual(proto.Extension.supported_versions, try extensions.decode(proto.Extension));
    var sv = try extensions.vector(u16);
    try testing.expectEqual(proto.Version.tls_1_3, try sv.decode(proto.Version));
    try sv.expectEof();

    try testing.expectEqual(proto.Extension.key_share, try extensions.decode(proto.Extension));
    var ks = try extensions.vector(u16);
    try testing.expectEqual(proto.NamedGroup.x25519, try ks.decode(proto.NamedGroup));
    try testing.expectEqualSlices(u8, &data13.server_pub_key, try ks.vectorBytes(u16));
    try ks.expectEof();
    try extensions.expectEof();
}

test "decoder never reads past the end" {
    var d = Decoder.init(&.{ 0x00, 0x03, 0xaa });
    try testing.expectError(error.TlsDecodeError, d.vector(u16)); // says 3, has 1
    d = Decoder.init(&.{ 0x00, 0x03, 0xaa });
    try testing.expectEqual(3, try d.decode(u16));
    try testing.expectError(error.TlsDecodeError, d.slice(2));
    try testing.expectError(error.TlsDecodeError, d.decode(u16));
    try testing.expectEqual(0xaa, try d.decode(u8));
    try d.expectEof();
    try testing.expectError(error.TlsDecodeError, d.decode(u8));
    try testing.expectError(error.TlsDecodeError, d.skip(1));
    try d.skip(0);
}

test "writer builds the example ServerHello" {
    var buf: [256]u8 = undefined;
    var w = Writer.init(&buf);
    try w.enumValue(proto.ContentType.handshake);
    try w.enumValue(proto.Version.tls_1_2);
    const record_len = try w.beginLength(u16);
    try w.enumValue(proto.HandshakeType.server_hello);
    const hello_len = try w.beginLength(u24);
    try w.enumValue(proto.Version.tls_1_2);
    try w.slice(&data13.server_random);
    try w.vector(u8, data13.client_hello[5 + 4 + 2 + 32 + 1 ..][0..32]); // echoed session id
    try w.enumValue(proto.CipherSuite.aes_256_gcm_sha384);
    try w.byte(0);
    const ext_len = try w.beginLength(u16);
    try w.enumValue(proto.Extension.supported_versions);
    try w.vector(u16, &.{ 0x03, 0x04 });
    try w.enumValue(proto.Extension.key_share);
    const ks_len = try w.beginLength(u16);
    try w.enumValue(proto.NamedGroup.x25519);
    try w.vector(u16, &data13.server_pub_key);
    try ks_len.end(&w);
    try ext_len.end(&w);
    try hello_len.end(&w);
    try record_len.end(&w);
    try testing.expectEqualSlices(u8, &data13.server_hello, w.written());
}

test "writer refuses what does not fit" {
    var buf: [4]u8 = undefined;
    var w = Writer.init(&buf);
    try w.int(u16, 1);
    try testing.expectError(error.OutputBufferUndersize, w.slice("abc"));
    try testing.expectError(error.OutputBufferUndersize, w.int(u24, 1));
    try w.enumList([_]proto.NamedGroup{});
    try testing.expectEqualSlices(u8, &.{ 0, 1, 0, 0 }, w.written());
    try testing.expectError(error.OutputBufferUndersize, w.byte(0));
    try testing.expectEqual(0, w.unused().len);
}

test "a length prefix that cannot hold its contents" {
    var buf: [300]u8 = undefined;
    var w = Writer.init(&buf);
    const len = try w.beginLength(u8);
    _ = try w.writable(256);
    try testing.expectError(error.LengthOverflow, len.end(&w));
    w = Writer.init(&buf);
    try testing.expectError(error.LengthOverflow, w.vector(u8, buf[0..256]));
}
