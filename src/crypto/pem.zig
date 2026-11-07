//! PEM (RFC 7468) decoding, done here so that AWS-LC only ever sees DER
//! bytes and never does I/O of its own.

const std = @import("std");

pub const Error = error{InvalidPem};

pub const Block = struct {
    /// What the markers say, e.g. "CERTIFICATE" or "EC PRIVATE KEY".
    label: []const u8,
    /// The base64 text between the markers, whitespace included.
    body: []const u8,

    pub fn decodedSizeUpperBound(self: Block) usize {
        // Whitespace in the body only makes this bound looser.
        return (self.body.len + 3) / 4 * 3;
    }

    /// Decodes into `out`, which needs `decodedSizeUpperBound` bytes.
    pub fn decode(self: Block, out: []u8) Error![]u8 {
        const n = decoder.decode(out, self.body) catch return error.InvalidPem;
        return out[0..n];
    }
};

const decoder = std.base64.standard.decoderWithIgnore(" \t\r\n");

/// Walks the blocks of a PEM file in order, skipping text between them.
pub const Iterator = struct {
    rest: []const u8,

    pub fn init(pem: []const u8) Iterator {
        return .{ .rest = pem };
    }

    pub fn next(self: *Iterator) Error!?Block {
        const begin = "-----BEGIN ";
        const end = "-----END ";
        const dashes = "-----";

        const begin_at = std.mem.indexOf(u8, self.rest, begin) orelse {
            self.rest = &.{};
            return null;
        };
        const label_start = begin_at + begin.len;
        const label_end = std.mem.indexOfPos(u8, self.rest, label_start, dashes) orelse return error.InvalidPem;
        const label = self.rest[label_start..label_end];
        const body_start = label_end + dashes.len;

        const body_end = std.mem.indexOfPos(u8, self.rest, body_start, end) orelse return error.InvalidPem;
        const end_label_start = body_end + end.len;
        if (!std.mem.startsWith(u8, self.rest[end_label_start..], label)) return error.InvalidPem;
        const end_dashes = end_label_start + label.len;
        if (!std.mem.startsWith(u8, self.rest[end_dashes..], dashes)) return error.InvalidPem;

        const block: Block = .{ .label = label, .body = self.rest[body_start..body_end] };
        self.rest = self.rest[end_dashes + dashes.len ..];
        return block;
    }
};

const testing = std.testing;

test "two blocks with text between" {
    const pem =
        \\some comment
        \\-----BEGIN CERTIFICATE-----
        \\aGVsbG8=
        \\-----END CERTIFICATE-----
        \\another comment
        \\-----BEGIN EC PRIVATE KEY-----
        \\d29y
        \\bGQ=
        \\-----END EC PRIVATE KEY-----
        \\
    ;
    var it = Iterator.init(pem);
    var buf: [64]u8 = undefined;

    const a = (try it.next()).?;
    try testing.expectEqualStrings("CERTIFICATE", a.label);
    try testing.expectEqualStrings("hello", try a.decode(buf[0..a.decodedSizeUpperBound()]));

    const b = (try it.next()).?;
    try testing.expectEqualStrings("EC PRIVATE KEY", b.label);
    try testing.expectEqualStrings("world", try b.decode(buf[0..b.decodedSizeUpperBound()]));

    try testing.expectEqual(null, try it.next());
    try testing.expectEqual(null, try it.next());
}

test "malformed input" {
    var it = Iterator.init("-----BEGIN X-----\nYWJj\n");
    try testing.expectError(error.InvalidPem, it.next());
    it = Iterator.init("-----BEGIN X-----\nYWJj\n-----END Y-----\n");
    try testing.expectError(error.InvalidPem, it.next());
    it = Iterator.init("-----BEGIN X-----\n!!!!\n-----END X-----\n");
    const block = (try it.next()).?;
    var buf: [8]u8 = undefined;
    try testing.expectError(error.InvalidPem, block.decode(&buf));
    it = Iterator.init("no blocks here");
    try testing.expectEqual(null, try it.next());
}
