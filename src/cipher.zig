//! Record protection (RFC 9846 §5.2): the keys of one direction, sealing
//! and opening records in one AEAD pass, and the per-key-generation
//! limits.

const std = @import("std");
const assert = std.debug.assert;
const crypto = @import("crypto.zig");
const aead = crypto.aead;
const hash = crypto.hash;
const hkdf = crypto.hkdf;
const proto = @import("protocol.zig");
const key_schedule = @import("key_schedule.zig");
const Secret = key_schedule.Secret;

pub const header_len = 5;
/// The most application data one record may carry.
pub const max_plaintext_len = 1 << 14;
/// Content type and tag, around the plaintext of every record we seal.
pub const seal_overhead = 1 + aead.tag_length;
/// The longest encrypted record body a peer may send (§5.2).
pub const max_ciphertext_len = max_plaintext_len + 256;
/// The longest record a peer may send, header included: the input buffer
/// must hold one.
pub const max_record_len = header_len + max_ciphertext_len;
/// The longest record we seal, header included.
pub const max_sealed_record_len = header_len + max_plaintext_len + seal_overhead;

pub fn suiteAead(suite: proto.CipherSuite) ?aead.Algorithm {
    return switch (suite) {
        .aes_128_gcm_sha256 => .aes_128_gcm,
        .aes_256_gcm_sha384 => .aes_256_gcm,
        .chacha20_poly1305_sha256 => .chacha20_poly1305,
        _ => null,
    };
}

pub fn suiteHash(suite: proto.CipherSuite) ?hash.Algorithm {
    return switch (suite) {
        .aes_128_gcm_sha256, .chacha20_poly1305_sha256 => .sha256,
        .aes_256_gcm_sha384 => .sha384,
        _ => null,
    };
}

/// The record header every protected record carries: application_data,
/// the legacy version, and the body length.
pub fn header(body_len: usize) [header_len]u8 {
    assert(body_len <= max_ciphertext_len);
    var h: [header_len]u8 = undefined;
    h[0] = @intFromEnum(proto.ContentType.application_data);
    std.mem.writeInt(u16, h[1..3], @intFromEnum(proto.Version.tls_1_2), .big);
    std.mem.writeInt(u16, h[3..5], @intCast(body_len), .big);
    return h;
}

pub const Opened = struct {
    content_type: proto.ContentType,
    /// The plaintext, without the content type and padding.
    len: usize,
};

/// One direction's keys: the traffic secret they came from, the keyed AEAD,
/// the IV and the record sequence number.
pub const Keys = struct {
    algorithm: aead.Algorithm,
    hash_algorithm: hash.Algorithm,
    secret: Secret,
    ctx: aead.Context,
    iv: aead.Nonce,
    seq: u64 = 0,

    pub fn init(suite: proto.CipherSuite, traffic_secret: Secret) crypto.err.Error!Keys {
        var keys: Keys = .{
            .algorithm = suiteAead(suite).?,
            .hash_algorithm = suiteHash(suite).?,
            .secret = traffic_secret,
            .ctx = undefined,
            .iv = undefined,
        };
        try keys.deriveKeys();
        return keys;
    }

    fn deriveKeys(keys: *Keys) crypto.err.Error!void {
        var key: [aead.max_key_length]u8 = undefined;
        defer std.crypto.secureZero(u8, &key);
        const key_len = keys.algorithm.keyLength();
        hkdf.expandLabel(keys.hash_algorithm, keys.secret.slice(), "key", "", key[0..key_len]);
        hkdf.expandLabel(keys.hash_algorithm, keys.secret.slice(), "iv", "", &keys.iv);
        keys.ctx = try aead.Context.init(keys.algorithm, key[0..key_len]);
        keys.seq = 0;
    }

    pub fn deinit(keys: *Keys) void {
        keys.ctx.deinit();
        keys.secret.wipe();
        std.crypto.secureZero(u8, &keys.iv);
        keys.* = undefined;
    }

    /// Moves to the next generation of keys (§7.2), after a KeyUpdate was
    /// sent or received. On failure the keys are left as they were.
    pub fn update(keys: *Keys) crypto.err.Error!void {
        var next: Keys = .{
            .algorithm = keys.algorithm,
            .hash_algorithm = keys.hash_algorithm,
            .secret = key_schedule.nextTrafficSecret(keys.hash_algorithm, &keys.secret),
            .ctx = undefined,
            .iv = undefined,
        };
        next.deriveKeys() catch |err| {
            next.secret.wipe();
            return err;
        };
        keys.deinit();
        keys.* = next;
    }

    /// How many records one generation of keys should seal before the
    /// sender updates them: for AES-GCM a little under the 2^24.5 that §5.5
    /// allows, so the update goes out with margin and a seal never fails.
    pub fn recordLimit(keys: *const Keys) u64 {
        return switch (keys.algorithm) {
            .aes_128_gcm, .aes_256_gcm => 1 << 24,
            .chacha20_poly1305 => 1 << 62,
        };
    }

    fn nonce(keys: *const Keys, seq: u64) aead.Nonce {
        var n = keys.iv;
        var seq_bytes: [8]u8 = undefined;
        std.mem.writeInt(u64, &seq_bytes, seq, .big);
        for (n[4..], seq_bytes) |*b, s| b.* ^= s;
        return n;
    }

    /// Seals a record in place. On entry `record[header_len..][0..len]`
    /// holds the plaintext; on return `record[0..sealedLen(len)]` is the
    /// record, ready to send. Fails only when this generation of keys is
    /// used up, which the sender prevents with a KeyUpdate.
    pub fn seal(keys: *Keys, record: []u8, content_type: proto.ContentType, len: usize) error{TlsInternalError}!void {
        assert(len <= max_plaintext_len);
        assert(record.len >= sealedLen(len));
        if (keys.seq == std.math.maxInt(u64)) return error.TlsInternalError;

        const body_len = len + seal_overhead;
        record[0..header_len].* = header(body_len);
        const inner = record[header_len..][0 .. len + 1];
        inner[len] = @intFromEnum(content_type);
        const tag = record[header_len + inner.len ..][0..aead.tag_length];
        keys.ctx.seal(&keys.nonce(keys.seq), record[0..header_len], inner, inner, tag);
        keys.seq += 1;
    }

    pub fn sealedLen(plaintext_len: usize) usize {
        return header_len + plaintext_len + seal_overhead;
    }

    /// The most inner plaintext (content, type byte and padding) a protected
    /// record may hold (§5.4), and so the most `open` writes to `out`.
    pub const max_inner_len = max_plaintext_len + 1;

    /// Opens `record` (header, ciphertext and tag) into `out`, which needs
    /// `record.len - header_len - tag_length` bytes (at most
    /// `max_inner_len`) and is either exactly `record[header_len..]` or
    /// disjoint from it. The content type and any padding are stripped from
    /// the result; only handshake, alert and application_data are accepted
    /// inside a protected record.
    pub fn open(keys: *Keys, record: []const u8, out: []u8) error{ TlsBadRecordMac, TlsDecodeError, TlsRecordOverflow, TlsUnexpectedMessage, TlsInternalError }!Opened {
        if (record.len < header_len + seal_overhead) return error.TlsDecodeError;
        if (record.len > max_record_len) return error.TlsRecordOverflow;
        const inner_len = record.len - header_len - aead.tag_length;
        if (inner_len > max_inner_len) return error.TlsRecordOverflow;
        assert(out.len >= inner_len);
        if (keys.seq == std.math.maxInt(u64)) return error.TlsInternalError;

        const ciphertext = record[header_len..][0..inner_len];
        const tag = record[header_len + inner_len ..][0..aead.tag_length];
        keys.ctx.open(&keys.nonce(keys.seq), record[0..header_len], ciphertext, tag, out[0..inner_len]) catch return error.TlsBadRecordMac;
        keys.seq += 1;

        // The content type is the last non-zero byte; what follows is padding.
        var i = inner_len;
        while (i > 0) {
            i -= 1;
            if (out[i] != 0) {
                const content_type: proto.ContentType = @enumFromInt(out[i]);
                return switch (content_type) {
                    .handshake, .alert, .application_data => .{ .content_type = content_type, .len = i },
                    else => error.TlsUnexpectedMessage,
                };
            }
        }
        return error.TlsUnexpectedMessage;
    }
};

const testing = std.testing;
const data13 = @import("testdata/tls13.zig");

fn exampleKeys(secret_key: []const u8, iv: *const [12]u8) !Keys {
    // The example gives the key and IV rather than the traffic secret, so
    // build the keys directly.
    var keys: Keys = .{
        .algorithm = .aes_256_gcm,
        .hash_algorithm = .sha384,
        .secret = .{ .bytes = @splat(0), .len = 48 },
        .ctx = try aead.Context.init(.aes_256_gcm, secret_key),
        .iv = iv.*,
    };
    _ = &keys;
    return keys;
}

test "opening the example connection's records" {
    var server = try exampleKeys(&data13.server_handshake_key, &data13.server_handshake_iv);
    defer server.deinit();
    var buf: [1024]u8 = undefined;
    const ee = try server.open(&data13.server_encrypted_extensions_wrapped, &buf);
    try testing.expectEqual(proto.ContentType.handshake, ee.content_type);
    try testing.expectEqualSlices(u8, &data13.server_encrypted_extensions, buf[0..ee.len]);
    const cert = try server.open(&data13.server_certificate_wrapped, &buf);
    try testing.expectEqualSlices(u8, &data13.server_certificate, buf[0..cert.len]);
    try testing.expectEqual(2, server.seq);
    // In place.
    var rec = data13.server_certificate_verify_wrapped;
    const cv = try server.open(&rec, rec[header_len..]);
    try testing.expectEqual(proto.ContentType.handshake, cv.content_type);
    try testing.expectEqual(proto.HandshakeType.certificate_verify, @as(proto.HandshakeType, @enumFromInt(rec[header_len])));
    // A wrong sequence number fails the tag.
    var again = data13.server_finished_wrapped;
    server.seq = 7;
    try testing.expectError(error.TlsBadRecordMac, server.open(&again, again[header_len..]));
}

test "sealing reproduces the example record" {
    var client = try exampleKeys(&data13.client_application_key, &data13.client_application_iv);
    defer client.deinit();
    var record: [Keys.sealedLen(4)]u8 = undefined;
    record[header_len..][0..4].* = "ping".*;
    try client.seal(&record, .application_data, 4);
    try testing.expectEqualSlices(u8, &data13.client_ping_wrapped, &record);
    try testing.expectEqual(1, client.seq);
}

test "round trip through a derived generation and a key update" {
    for (proto.CipherSuite.all) |suite| {
        const ks = key_schedule.KeySchedule.init(suiteHash(suite).?);
        const secret = ks.trafficSecret(.client_application, "transcript");
        var sender = try Keys.init(suite, secret);
        defer sender.deinit();
        var receiver = try Keys.init(suite, secret);
        defer receiver.deinit();

        var record: [Keys.sealedLen(max_plaintext_len)]u8 = undefined;
        for ([_]usize{ 0, 1, 100, max_plaintext_len }) |len| {
            @memset(record[header_len..][0..len], 'x');
            try sender.seal(&record, .handshake, len);
            try testing.expectEqualSlices(u8, &header(len + seal_overhead), record[0..header_len]);
            try testing.expectEqual(proto.ContentType.application_data, @as(proto.ContentType, @enumFromInt(record[0])));
            var out: [max_plaintext_len + 1]u8 = undefined;
            const opened = try receiver.open(record[0..Keys.sealedLen(len)], &out);
            try testing.expectEqual(proto.ContentType.handshake, opened.content_type);
            try testing.expectEqual(len, opened.len);
            try testing.expect(std.mem.allEqual(u8, out[0..len], 'x'));
        }

        try sender.update();
        try testing.expectEqual(0, sender.seq);
        record[header_len..][0..5].* = "hello".*;
        try sender.seal(&record, .application_data, 5);
        var out: [64]u8 = undefined;
        try testing.expectError(error.TlsBadRecordMac, receiver.open(record[0..Keys.sealedLen(5)], &out));
        try receiver.update();
        receiver.seq = 0;
        const opened = try receiver.open(record[0..Keys.sealedLen(5)], &out);
        try testing.expectEqualSlices(u8, "hello", out[0..opened.len]);
    }
}

test "padding is stripped and an all-zero plaintext is rejected" {
    const ks = key_schedule.KeySchedule.init(.sha256);
    const secret = ks.trafficSecret(.server_application, "t");
    var sender = try Keys.init(.aes_128_gcm_sha256, secret);
    defer sender.deinit();
    var receiver = try Keys.init(.aes_128_gcm_sha256, secret);
    defer receiver.deinit();

    // Seal the inner plaintext by hand so the content type is followed by
    // padding, which `seal` never adds.
    var inner: [11]u8 = @splat(0);
    inner[0..2].* = "ab".*;
    inner[2] = @intFromEnum(proto.ContentType.alert);
    var record: [header_len + inner.len + aead.tag_length]u8 = undefined;
    record[0..header_len].* = header(inner.len + aead.tag_length);
    const n = sender.nonce(sender.seq);
    sender.ctx.seal(&n, record[0..header_len], &inner, record[header_len..][0..inner.len], record[header_len + inner.len ..][0..aead.tag_length]);
    sender.seq += 1;
    var out: [64]u8 = undefined;
    const opened = try receiver.open(&record, &out);
    try testing.expectEqual(proto.ContentType.alert, opened.content_type);
    try testing.expectEqualSlices(u8, "ab", out[0..opened.len]);

    inner = @splat(0);
    const n2 = sender.nonce(sender.seq);
    sender.ctx.seal(&n2, record[0..header_len], &inner, record[header_len..][0..inner.len], record[header_len + inner.len ..][0..aead.tag_length]);
    try testing.expectError(error.TlsUnexpectedMessage, receiver.open(&record, &out));

    try testing.expectError(error.TlsDecodeError, receiver.open(record[0 .. header_len + aead.tag_length], &out));

    // change_cipher_spec may not hide inside a protected record.
    inner = @splat(0);
    inner[0] = @intFromEnum(proto.ContentType.change_cipher_spec);
    sender.seq = 2;
    receiver.seq = 2;
    const n3 = sender.nonce(sender.seq);
    sender.ctx.seal(&n3, record[0..header_len], &inner, record[header_len..][0..inner.len], record[header_len + inner.len ..][0..aead.tag_length]);
    try testing.expectError(error.TlsUnexpectedMessage, receiver.open(&record, &out));
}

test "oversized records are record_overflow" {
    const ks = key_schedule.KeySchedule.init(.sha256);
    var keys = try Keys.init(.aes_128_gcm_sha256, ks.trafficSecret(.server_application, "t"));
    defer keys.deinit();
    var out: [max_record_len]u8 = undefined;
    var record: [max_record_len + 1]u8 = undefined;
    record[0..header_len].* = header(max_ciphertext_len);
    try testing.expectError(error.TlsRecordOverflow, keys.open(&record, &out));
    // Within the body limit but more inner plaintext than §5.4 allows.
    const too_much = header_len + Keys.max_inner_len + 1 + aead.tag_length;
    try testing.expectError(error.TlsRecordOverflow, keys.open(record[0..too_much], &out));
}
