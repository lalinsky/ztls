//! Record protection: the keys of one direction, sealing and opening
//! records in one AEAD pass, and the per-key-generation limits. TLS 1.3
//! records (RFC 9846 §5.2) by default, TLS 1.2 AEAD records (RFC 5246
//! §6.2.3.3, RFC 5288, RFC 7905) for keys made with `initTls12`.

const std = @import("std");
const assert = std.debug.assert;
const crypto = @import("../crypto.zig");
const aead = crypto.aead;
const hash = crypto.hash;
const hkdf = crypto.hkdf;
const proto = @import("../protocol.zig");
const key_schedule = @import("key_schedule.zig");
const Secret = key_schedule.Secret;

pub const header_len = 5;
/// The most application data one record may carry.
pub const max_plaintext_len = 1 << 14;
/// What a TLS 1.3 record we seal adds around its plaintext: the content
/// type and the tag.
pub const seal_overhead = 1 + aead.tag_length;
/// What a TLS 1.2 AES-GCM record adds, the most of any record we seal: the
/// explicit nonce before the plaintext and the tag after it.
pub const max_seal_overhead = tls12_explicit_nonce_len + aead.tag_length;
/// The longest encrypted record body a peer may send (§5.2). A TLS 1.2
/// peer may send up to 2^14 + 2048, but no AEAD record whose plaintext
/// fits in 2^14 comes near this.
pub const max_ciphertext_len = max_plaintext_len + 256;
/// The longest record a peer may send, header included: the input buffer
/// must hold one.
pub const max_record_len = header_len + max_ciphertext_len;
/// The longest record we seal, header included, in either version.
pub const max_sealed_record_len = header_len + max_plaintext_len + max_seal_overhead;

/// The part of a TLS 1.2 AES-GCM nonce sent in each record (RFC 5288 §3).
const tls12_explicit_nonce_len = 8;
/// The part kept from the key block: the salt for AES-GCM, the whole IV
/// for ChaCha20 (RFC 7905 §2).
pub fn tls12FixedIvLen(algorithm: aead.Algorithm) usize {
    return switch (algorithm) {
        .aes_128_gcm, .aes_256_gcm => 4,
        .chacha20_poly1305 => aead.nonce_length,
    };
}

pub const Version = @import("../policy.zig").Version;

/// What TLS 1.3 keys keep for KeyUpdate: the traffic secret they came
/// from and its hash.
pub const Tls13 = struct {
    hash_algorithm: hash.Algorithm,
    secret: Secret,
};

/// The record AEAD of a TLS 1.3 or TLS 1.2 suite.
pub fn suiteAead(suite: proto.CipherSuite) ?aead.Algorithm {
    return switch (suite) {
        .aes_128_gcm_sha256, .ecdhe_ecdsa_with_aes_128_gcm_sha256, .ecdhe_rsa_with_aes_128_gcm_sha256 => .aes_128_gcm,
        .aes_256_gcm_sha384, .ecdhe_ecdsa_with_aes_256_gcm_sha384, .ecdhe_rsa_with_aes_256_gcm_sha384 => .aes_256_gcm,
        .chacha20_poly1305_sha256, .ecdhe_ecdsa_with_chacha20_poly1305_sha256, .ecdhe_rsa_with_chacha20_poly1305_sha256 => .chacha20_poly1305,
        else => null,
    };
}

/// The hash of a suite's key schedule and transcript: HKDF's in TLS 1.3,
/// the PRF's in TLS 1.2.
pub fn suiteHash(suite: proto.CipherSuite) ?hash.Algorithm {
    return switch (suite) {
        .aes_128_gcm_sha256,
        .chacha20_poly1305_sha256,
        .ecdhe_ecdsa_with_aes_128_gcm_sha256,
        .ecdhe_rsa_with_aes_128_gcm_sha256,
        .ecdhe_ecdsa_with_chacha20_poly1305_sha256,
        .ecdhe_rsa_with_chacha20_poly1305_sha256,
        => .sha256,
        .aes_256_gcm_sha384, .ecdhe_ecdsa_with_aes_256_gcm_sha384, .ecdhe_rsa_with_aes_256_gcm_sha384 => .sha384,
        else => null,
    };
}

/// The record header every TLS 1.3 protected record carries:
/// application_data, the legacy version, and the body length.
pub fn header(body_len: usize) [header_len]u8 {
    return headerOf(.application_data, body_len);
}

/// A record header: in TLS 1.2 the real content type goes outside.
fn headerOf(content_type: proto.ContentType, body_len: usize) [header_len]u8 {
    assert(body_len <= max_ciphertext_len);
    var h: [header_len]u8 = undefined;
    h[0] = @intFromEnum(content_type);
    std.mem.writeInt(u16, h[1..3], @intFromEnum(proto.Version.tls_1_2), .big);
    std.mem.writeInt(u16, h[3..5], @intCast(body_len), .big);
    return h;
}

pub const Opened = struct {
    content_type: proto.ContentType,
    /// The plaintext, without the content type and padding.
    len: usize,
};

/// One direction's keys: the keyed AEAD, the IV, the record sequence
/// number, and in TLS 1.3 the traffic secret they came from.
pub const Keys = struct {
    /// The record format, and for TLS 1.3 what KeyUpdate needs; TLS 1.2
    /// has no key updates.
    version: union(Version) {
        tls13: Tls13,
        tls12,
    },
    algorithm: aead.Algorithm,
    ctx: aead.Context,
    /// TLS 1.3 and TLS 1.2 ChaCha20: the IV the sequence number is XORed
    /// into. TLS 1.2 AES-GCM: the 4-byte salt, then zeros where the
    /// explicit nonce goes.
    iv: aead.Nonce,
    seq: u64 = 0,

    pub fn init(suite: proto.CipherSuite, traffic_secret: Secret) crypto.err.Error!Keys {
        return fromSecret(suiteAead(suite).?, .{ .hash_algorithm = suiteHash(suite).?, .secret = traffic_secret });
    }

    /// TLS 1.2 keys from the key block's write key and fixed IV
    /// (`tls12FixedIvLen` bytes). The record sequence number starts at 0
    /// and is also the AES-GCM explicit nonce, as AWS-LC and s2n do.
    pub fn initTls12(algorithm: aead.Algorithm, key: []const u8, fixed_iv: []const u8) crypto.err.Error!Keys {
        if (!proto.tls12_enabled) unreachable;
        assert(fixed_iv.len == tls12FixedIvLen(algorithm));
        var keys: Keys = .{
            .version = .tls12,
            .algorithm = algorithm,
            .ctx = try aead.Context.initTls12(algorithm, key),
            .iv = @splat(0),
        };
        @memcpy(keys.iv[0..fixed_iv.len], fixed_iv);
        return keys;
    }

    /// TLS 1.3 keys from a traffic secret (§7.3). On failure the secret
    /// is left to the caller.
    fn fromSecret(algorithm: aead.Algorithm, tls13: Tls13) crypto.err.Error!Keys {
        var key: [aead.max_key_length]u8 = undefined;
        defer std.crypto.secureZero(u8, &key);
        const key_len = algorithm.keyLength();
        var iv: aead.Nonce = undefined;
        hkdf.expandLabel(tls13.hash_algorithm, tls13.secret.slice(), "key", "", key[0..key_len]);
        hkdf.expandLabel(tls13.hash_algorithm, tls13.secret.slice(), "iv", "", &iv);
        return .{
            .version = .{ .tls13 = tls13 },
            .algorithm = algorithm,
            .ctx = try aead.Context.init(algorithm, key[0..key_len]),
            .iv = iv,
        };
    }

    pub fn deinit(keys: *Keys) void {
        keys.ctx.deinit();
        switch (keys.version) {
            .tls13 => |*tls13| tls13.secret.wipe(),
            .tls12 => {},
        }
        std.crypto.secureZero(u8, &keys.iv);
        keys.* = undefined;
    }

    /// Moves to the next generation of keys (§7.2), after a KeyUpdate was
    /// sent or received. Only TLS 1.3 keys have a next generation, so the
    /// caller passes `&keys.version.tls13`, having switched on the version.
    /// On failure the keys are left as they were.
    pub fn update(keys: *Keys, tls13: *const Tls13) crypto.err.Error!void {
        assert(tls13 == &keys.version.tls13);
        var next_secret = key_schedule.nextTrafficSecret(tls13.hash_algorithm, &tls13.secret);
        defer next_secret.wipe();
        var next = try fromSecret(keys.algorithm, .{ .hash_algorithm = tls13.hash_algorithm, .secret = next_secret });
        keys.deinit();
        keys.* = next;
        // The copy now lives in `keys`; leave no secret behind on the stack.
        std.crypto.secureZero(u8, std.mem.asBytes(&next));
    }

    /// Moves `keys` into `slot`, in place of the keys there, which are
    /// freed only now that the new ones exist. The copy in `keys` is wiped.
    pub fn replace(slot: *?Keys, keys: *Keys) void {
        if (slot.*) |*old| old.deinit();
        slot.* = keys.*;
        std.crypto.secureZero(u8, std.mem.asBytes(keys));
    }

    /// How many records one generation of keys may seal before the sender
    /// updates them: for TLS 1.3 AES-GCM a little under the 2^24.5 that
    /// §5.5 allows, so the update goes out with margin. TLS 1.2 has no key
    /// update to go to, so it runs until the sequence number would wrap,
    /// as s2n does; AWS-LC refuses the last explicit nonce, 2^64 - 1.
    pub fn recordLimit(keys: *const Keys) u64 {
        return switch (keys.version) {
            .tls13 => switch (keys.algorithm) {
                .aes_128_gcm, .aes_256_gcm => 1 << 24,
                .chacha20_poly1305 => 1 << 62,
            },
            .tls12 => std.math.maxInt(u64) - 1,
        };
    }

    fn explicitNonceLen(keys: *const Keys) usize {
        return switch (keys.version) {
            .tls13 => 0,
            .tls12 => switch (keys.algorithm) {
                .aes_128_gcm, .aes_256_gcm => tls12_explicit_nonce_len,
                .chacha20_poly1305 => 0,
            },
        };
    }

    /// Where a record's plaintext starts: after the header, and in TLS 1.2
    /// AES-GCM after the explicit nonce.
    pub fn payloadOffset(keys: *const Keys) usize {
        return header_len + keys.explicitNonceLen();
    }

    /// What follows a record's plaintext: the content type (TLS 1.3) and
    /// the tag.
    pub fn trailerLen(keys: *const Keys) usize {
        return switch (keys.version) {
            .tls13 => seal_overhead,
            .tls12 => aead.tag_length,
        };
    }

    /// A record of `plaintext_len` bytes as sealed, header included.
    pub fn sealedLen(keys: *const Keys, plaintext_len: usize) usize {
        return keys.payloadOffset() + plaintext_len + keys.trailerLen();
    }

    /// A TLS 1.3 record of `plaintext_len` bytes as sealed, header included.
    pub fn sealedLenTls13(plaintext_len: usize) usize {
        return header_len + plaintext_len + seal_overhead;
    }

    fn nonce(keys: *const Keys, seq: u64) aead.Nonce {
        var n = keys.iv;
        var seq_bytes: [8]u8 = undefined;
        std.mem.writeInt(u64, &seq_bytes, seq, .big);
        if (keys.explicitNonceLen() == 0) {
            for (n[4..], seq_bytes) |*b, s| b.* ^= s;
        } else {
            n[4..].* = seq_bytes;
        }
        return n;
    }

    /// The TLS 1.2 additional data: seq_num ‖ type ‖ version ‖ length of
    /// the plaintext (RFC 5246 §6.2.3.3).
    fn tls12Ad(seq: u64, content_type: proto.ContentType, plaintext_len: usize) [13]u8 {
        var ad: [13]u8 = undefined;
        std.mem.writeInt(u64, ad[0..8], seq, .big);
        ad[8..13].* = headerOf(content_type, plaintext_len);
        return ad;
    }

    /// Seals a record in place. On entry `record[payloadOffset()..][0..len]`
    /// holds the plaintext; on return `record[0..sealedLen(len)]` is the
    /// record, ready to send. Fails only past this generation's
    /// `recordLimit` (§5.5), which the TLS 1.3 sender's KeyUpdate normally
    /// forestalls; the record at the limit itself is that KeyUpdate, or
    /// an alert that ends the direction.
    pub fn seal(keys: *Keys, record: []u8, content_type: proto.ContentType, len: usize) error{TlsInternalError}!void {
        @setRuntimeSafety(true);
        assert(len <= max_plaintext_len);
        assert(record.len >= keys.sealedLen(len));
        if (keys.seq > keys.recordLimit()) return error.TlsInternalError;

        const n = keys.nonce(keys.seq);
        switch (keys.version) {
            .tls13 => {
                record[0..header_len].* = header(len + seal_overhead);
                const inner = record[header_len..][0 .. len + 1];
                inner[len] = @intFromEnum(content_type);
                const tag = record[header_len + inner.len ..][0..aead.tag_length];
                keys.ctx.seal(&n, record[0..header_len], inner, inner, tag);
            },
            .tls12 => {
                if (!proto.tls12_enabled) unreachable;
                const explicit = keys.explicitNonceLen();
                record[0..header_len].* = headerOf(content_type, explicit + len + aead.tag_length);
                @memcpy(record[header_len..][0..explicit], n[aead.nonce_length - explicit ..]);
                const plaintext = record[header_len + explicit ..][0..len];
                const tag = record[header_len + explicit + len ..][0..aead.tag_length];
                const ad = tls12Ad(keys.seq, content_type, len);
                keys.ctx.seal(&n, &ad, plaintext, plaintext, tag);
            },
        }
        keys.seq += 1;
    }

    /// The most inner plaintext (content, type byte and padding) a protected
    /// record may hold (§5.4), and so the most `open` writes to `out`.
    pub const max_inner_len = max_plaintext_len + 1;

    /// How many bytes `open` writes to `out` for a record of `record_len`
    /// bytes, header included; 0 for one too short to open.
    pub fn openLen(keys: *const Keys, record_len: usize) usize {
        return record_len -| (keys.payloadOffset() + aead.tag_length);
    }

    /// Opens `record` (header, explicit nonce, ciphertext and tag) into
    /// `out`, which needs `openLen(record.len)` bytes (at most
    /// `max_inner_len`) and is either exactly `record[payloadOffset()..]`
    /// or disjoint from it. In TLS 1.3 the content type and any padding
    /// are stripped from the result; in TLS 1.2 the content type is the
    /// header's. Only handshake, alert and application_data are accepted
    /// inside a protected record.
    pub fn open(keys: *Keys, record: []const u8, out: []u8) error{ TlsBadRecordMac, TlsDecodeError, TlsRecordOverflow, TlsUnexpectedMessage, TlsInternalError }!Opened {
        if (record.len > max_record_len) return error.TlsRecordOverflow;
        if (keys.seq == std.math.maxInt(u64)) return error.TlsInternalError;
        return switch (keys.version) {
            .tls13 => keys.openTls13(record, out),
            .tls12 => if (!proto.tls12_enabled) unreachable else keys.openTls12(record, out),
        };
    }

    fn openTls13(keys: *Keys, record: []const u8, out: []u8) error{ TlsBadRecordMac, TlsDecodeError, TlsRecordOverflow, TlsUnexpectedMessage }!Opened {
        @setRuntimeSafety(true);
        if (record.len < header_len + seal_overhead) return error.TlsDecodeError;
        const inner_len = record.len - header_len - aead.tag_length;
        if (inner_len > max_inner_len) return error.TlsRecordOverflow;
        assert(out.len >= inner_len);

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

    fn openTls12(keys: *Keys, record: []const u8, out: []u8) error{ TlsBadRecordMac, TlsDecodeError, TlsRecordOverflow, TlsUnexpectedMessage }!Opened {
        @setRuntimeSafety(true);
        const content_type: proto.ContentType = @enumFromInt(record[0]);
        switch (content_type) {
            .handshake, .alert, .application_data => {},
            else => return error.TlsUnexpectedMessage,
        }
        const explicit = keys.explicitNonceLen();
        if (record.len < header_len + explicit + aead.tag_length) return error.TlsDecodeError;
        const len = record.len - header_len - explicit - aead.tag_length;
        if (len > max_plaintext_len) return error.TlsRecordOverflow;
        assert(out.len >= len);

        // AES-GCM takes the explicit nonce the sender chose, which need
        // not be its sequence number; ChaCha20 always uses ours.
        var n = keys.nonce(keys.seq);
        @memcpy(n[aead.nonce_length - explicit ..], record[header_len..][0..explicit]);
        const ciphertext = record[header_len + explicit ..][0..len];
        const tag = record[header_len + explicit + len ..][0..aead.tag_length];
        const ad = tls12Ad(keys.seq, content_type, len);
        keys.ctx.open(&n, &ad, ciphertext, tag, out[0..len]) catch return error.TlsBadRecordMac;
        keys.seq += 1;
        return .{ .content_type = content_type, .len = len };
    }
};

const testing = std.testing;
const data13 = @import("../testdata/tls13.zig");

fn exampleKeys(secret_key: []const u8, iv: *const [12]u8) !Keys {
    // The example gives the key and IV rather than the traffic secret, so
    // build the keys directly.
    return .{
        .version = .{ .tls13 = .{ .hash_algorithm = .sha384, .secret = .{ .bytes = @splat(0), .len = 48 } } },
        .algorithm = .aes_256_gcm,
        .ctx = try aead.Context.init(.aes_256_gcm, secret_key),
        .iv = iv.*,
    };
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
    var record: [Keys.sealedLenTls13(4)]u8 = undefined;
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

        var record: [Keys.sealedLenTls13(max_plaintext_len)]u8 = undefined;
        for ([_]usize{ 0, 1, 100, max_plaintext_len }) |len| {
            @memset(record[header_len..][0..len], 'x');
            try sender.seal(&record, .handshake, len);
            try testing.expectEqualSlices(u8, &header(len + seal_overhead), record[0..header_len]);
            try testing.expectEqual(proto.ContentType.application_data, @as(proto.ContentType, @enumFromInt(record[0])));
            var out: [max_plaintext_len + 1]u8 = undefined;
            const opened = try receiver.open(record[0..Keys.sealedLenTls13(len)], &out);
            try testing.expectEqual(proto.ContentType.handshake, opened.content_type);
            try testing.expectEqual(len, opened.len);
            try testing.expect(std.mem.allEqual(u8, out[0..len], 'x'));
        }

        try sender.update(&sender.version.tls13);
        try testing.expectEqual(0, sender.seq);
        record[header_len..][0..5].* = "hello".*;
        try sender.seal(&record, .application_data, 5);
        var out: [64]u8 = undefined;
        try testing.expectError(error.TlsBadRecordMac, receiver.open(record[0..Keys.sealedLenTls13(5)], &out));
        try receiver.update(&receiver.version.tls13);
        receiver.seq = 0;
        const opened = try receiver.open(record[0..Keys.sealedLenTls13(5)], &out);
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

/// TLS 1.2 keys for both ends of one direction.
fn tls12Pair(algorithm: aead.Algorithm) ![2]Keys {
    const key: [aead.max_key_length]u8 = @splat(0x3c);
    const iv: [aead.nonce_length]u8 = .{ 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac };
    const fixed = iv[0..tls12FixedIvLen(algorithm)];
    return .{
        try Keys.initTls12(algorithm, key[0..algorithm.keyLength()], fixed),
        try Keys.initTls12(algorithm, key[0..algorithm.keyLength()], fixed),
    };
}

test "TLS 1.2 records: layout, nonce and additional data" {
    if (!proto.tls12_enabled) return error.SkipZigTest;
    for ([_]aead.Algorithm{ .aes_128_gcm, .aes_256_gcm, .chacha20_poly1305 }) |algorithm| {
        var pair = try tls12Pair(algorithm);
        defer for (&pair) |*k| k.deinit();
        const sender = &pair[0];
        const receiver = &pair[1];
        const explicit: usize = if (algorithm == .chacha20_poly1305) 0 else 8;
        try testing.expectEqual(header_len + explicit, sender.payloadOffset());

        var record: [max_sealed_record_len]u8 = undefined;
        sender.seq = 0x0102030405060708;
        record[sender.payloadOffset()..][0..5].* = "hello".*;
        try sender.seal(&record, .handshake, 5);
        const sealed = record[0..sender.sealedLen(5)];
        try testing.expectEqual(header_len + explicit + 5 + aead.tag_length, sealed.len);
        // The real content type goes outside, and the body length counts
        // the explicit nonce and the tag.
        try testing.expectEqualSlices(u8, &.{ 22, 3, 3, 0, @intCast(explicit + 5 + 16) }, sealed[0..header_len]);
        // The explicit nonce is the sequence number.
        if (explicit > 0) try testing.expectEqualSlices(u8, &.{ 1, 2, 3, 4, 5, 6, 7, 8 }, sealed[header_len..][0..8]);

        // The same record built straight from RFC 5246 §6.2.3.3, RFC 5288
        // and RFC 7905 with the plain AEAD.
        {
            const key: [aead.max_key_length]u8 = @splat(0x3c);
            var ctx = try aead.Context.init(algorithm, key[0..algorithm.keyLength()]);
            defer ctx.deinit();
            var n: aead.Nonce = .{ 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac };
            const seq = [8]u8{ 1, 2, 3, 4, 5, 6, 7, 8 };
            if (explicit > 0) {
                n[4..].* = seq;
            } else {
                for (n[4..], seq) |*b, x| b.* ^= x;
            }
            const ad = seq ++ [_]u8{ 22, 3, 3, 0, 5 };
            var ct: [5]u8 = undefined;
            var tag: aead.Tag = undefined;
            ctx.seal(&n, &ad, "hello", &ct, &tag);
            try testing.expectEqualSlices(u8, &ct, sealed[header_len + explicit ..][0..5]);
            try testing.expectEqualSlices(u8, &tag, sealed[sealed.len - aead.tag_length ..]);
        }

        receiver.seq = sender.seq - 1;
        var out: [64]u8 = undefined;
        try testing.expectEqual(5, receiver.openLen(sealed.len));
        const opened = try receiver.open(sealed, &out);
        try testing.expectEqual(proto.ContentType.handshake, opened.content_type);
        try testing.expectEqualSlices(u8, "hello", out[0..opened.len]);
        try testing.expectEqual(sender.seq, receiver.seq);

        // The header is authenticated: another content type fails.
        receiver.seq -= 1;
        var retyped: [64]u8 = undefined;
        @memcpy(retyped[0..sealed.len], sealed);
        retyped[0] = @intFromEnum(proto.ContentType.application_data);
        try testing.expectError(error.TlsBadRecordMac, receiver.open(retyped[0..sealed.len], &out));
        // change_cipher_spec is never protected.
        retyped[0] = @intFromEnum(proto.ContentType.change_cipher_spec);
        try testing.expectError(error.TlsUnexpectedMessage, receiver.open(retyped[0..sealed.len], &out));
    }
}

test "TLS 1.2 round trips: empty, full and in place" {
    if (!proto.tls12_enabled) return error.SkipZigTest;
    for ([_]aead.Algorithm{ .aes_128_gcm, .aes_256_gcm, .chacha20_poly1305 }) |algorithm| {
        var pair = try tls12Pair(algorithm);
        defer for (&pair) |*k| k.deinit();
        const sender = &pair[0];
        const receiver = &pair[1];
        var record: [max_sealed_record_len]u8 = undefined;
        for ([_]usize{ 0, 1, 100, max_plaintext_len }) |len| {
            @memset(record[sender.payloadOffset()..][0..len], 'y');
            try sender.seal(&record, .application_data, len);
            const sealed = record[0..sender.sealedLen(len)];
            // In place: the plaintext lands where the ciphertext was.
            const opened = try receiver.open(sealed, record[receiver.payloadOffset()..]);
            try testing.expectEqual(proto.ContentType.application_data, opened.content_type);
            try testing.expectEqual(len, opened.len);
            try testing.expect(std.mem.allEqual(u8, record[receiver.payloadOffset()..][0..len], 'y'));
        }
        // Too short to hold the explicit nonce and tag.
        var out: [64]u8 = undefined;
        try testing.expectError(error.TlsDecodeError, receiver.open(record[0 .. receiver.payloadOffset() + aead.tag_length - 1], &out));
        // More plaintext than 2^14.
        var big: [max_record_len]u8 = undefined;
        const too_long = receiver.payloadOffset() + max_plaintext_len + 1 + aead.tag_length;
        big[0..header_len].* = headerOf(.application_data, too_long - header_len);
        var big_out: [max_record_len]u8 = undefined;
        try testing.expectError(error.TlsRecordOverflow, receiver.open(big[0..too_long], &big_out));
    }
}

test "TLS 1.2 keys run to the end of the sequence numbers" {
    if (!proto.tls12_enabled) return error.SkipZigTest;
    var pair = try tls12Pair(.aes_128_gcm);
    defer for (&pair) |*k| k.deinit();
    const sender = &pair[0];
    try testing.expectEqual(std.math.maxInt(u64) - 1, sender.recordLimit());
    var record: [max_sealed_record_len]u8 = undefined;
    sender.seq = std.math.maxInt(u64) - 1;
    try sender.seal(&record, .application_data, 0);
    try testing.expectError(error.TlsInternalError, sender.seal(&record, .application_data, 0));
}
