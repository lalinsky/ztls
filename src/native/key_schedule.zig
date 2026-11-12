//! The TLS 1.3 key schedule (RFC 9846 §7.1) and the transcript hash it
//! takes as input.

const std = @import("std");
const assert = std.debug.assert;
const crypto = @import("../crypto.zig");
const hash = crypto.hash;
const hkdf = crypto.hkdf;
const proto = @import("../protocol.zig");

/// A secret the size of the hash: a traffic secret, a finished key, a
/// stage of the schedule.
pub const Secret = struct {
    bytes: [hash.max_digest_length]u8,
    len: u8,

    pub fn slice(s: *const Secret) []const u8 {
        return s.bytes[0..s.len];
    }

    pub fn wipe(s: *Secret) void {
        std.crypto.secureZero(u8, &s.bytes);
        s.* = undefined;
    }
};

/// The running hash of the handshake messages. A client hashes its
/// ClientHello before the server picks the suite, so both hashes run until
/// `select`.
pub const Transcript = struct {
    sha256: hash.Sha256,
    sha384: hash.Sha384,
    selected: ?hash.Algorithm = null,

    pub fn init() Transcript {
        return .{ .sha256 = .init(), .sha384 = .init() };
    }

    pub fn update(t: *Transcript, bytes: []const u8) void {
        if (t.selected) |alg| switch (alg) {
            .sha256 => t.sha256.update(bytes),
            .sha384 => t.sha384.update(bytes),
        } else {
            t.sha256.update(bytes);
            t.sha384.update(bytes);
        }
    }

    pub fn select(t: *Transcript, algorithm: hash.Algorithm) void {
        assert(t.selected == null);
        t.selected = algorithm;
    }

    /// The hash of everything so far, which keeps running.
    pub fn digest(t: *const Transcript, out: *[hash.max_digest_length]u8) []const u8 {
        return switch (t.selected.?) {
            .sha256 => {
                out[0..hash.Sha256.digest_length].* = t.sha256.peek();
                return out[0..hash.Sha256.digest_length];
            },
            .sha384 => {
                out[0..hash.Sha384.digest_length].* = t.sha384.peek();
                return out[0..hash.Sha384.digest_length];
            },
        };
    }

    /// After a HelloRetryRequest the first ClientHello is replaced by a
    /// synthetic message_hash handshake message holding its hash
    /// (RFC 9846 §4.1).
    pub fn replaceWithMessageHash(t: *Transcript) void {
        var buf: [hash.max_digest_length]u8 = undefined;
        const h = t.digest(&buf);
        const header = [4]u8{ @intFromEnum(proto.HandshakeType.message_hash), 0, 0, @intCast(h.len) };
        t.sha256 = .init();
        t.sha384 = .init();
        t.update(&header);
        t.update(h);
    }
};

pub const TrafficLabel = enum {
    client_handshake,
    server_handshake,
    client_application,
    server_application,
    exporter_master,
    resumption_master,

    fn label(l: TrafficLabel) []const u8 {
        return switch (l) {
            .client_handshake => "c hs traffic",
            .server_handshake => "s hs traffic",
            .client_application => "c ap traffic",
            .server_application => "s ap traffic",
            .exporter_master => "exp master",
            .resumption_master => "res master",
        };
    }
};

/// Walks the schedule: early secret, then handshake secret once the shared
/// secret is in, then master secret. Traffic secrets are derived from the
/// current stage and the transcript hash of the moment.
pub const KeySchedule = struct {
    algorithm: hash.Algorithm,
    /// The current stage: early, handshake or master secret.
    secret: Secret,

    /// Starts at the early secret, with no PSK (v1 has no resumption).
    pub fn init(algorithm: hash.Algorithm) KeySchedule {
        const zeros: [hash.max_digest_length]u8 = @splat(0);
        var ks: KeySchedule = .{ .algorithm = algorithm, .secret = undefined };
        const n = algorithm.digestLength();
        _ = hkdf.extract(algorithm, zeros[0..n], zeros[0..n], &ks.secret.bytes);
        ks.secret.len = @intCast(n);
        return ks;
    }

    pub fn deinit(ks: *KeySchedule) void {
        ks.secret.wipe();
        ks.* = undefined;
    }

    /// Early secret -> handshake secret, from the (EC)DHE shared secret.
    pub fn deriveHandshakeSecret(ks: *KeySchedule, shared_secret: []const u8) void {
        ks.advance(shared_secret);
    }

    /// Handshake secret -> master secret.
    pub fn deriveMasterSecret(ks: *KeySchedule) void {
        const zeros: [hash.max_digest_length]u8 = @splat(0);
        ks.advance(zeros[0..ks.algorithm.digestLength()]);
    }

    fn advance(ks: *KeySchedule, ikm: []const u8) void {
        const empty_hash = emptyHash(ks.algorithm);
        var derived: [hash.max_digest_length]u8 = undefined;
        defer std.crypto.secureZero(u8, &derived);
        const d = hkdf.deriveSecret(ks.algorithm, ks.secret.slice(), "derived", empty_hash.slice(), &derived);
        _ = hkdf.extract(ks.algorithm, d, ikm, &ks.secret.bytes);
    }

    pub fn trafficSecret(ks: *const KeySchedule, which: TrafficLabel, transcript_hash: []const u8) Secret {
        var s: Secret = .{ .bytes = undefined, .len = ks.secret.len };
        _ = hkdf.deriveSecret(ks.algorithm, ks.secret.slice(), which.label(), transcript_hash, &s.bytes);
        return s;
    }
};

fn emptyHash(algorithm: hash.Algorithm) Secret {
    var s: Secret = .{ .bytes = undefined, .len = @intCast(algorithm.digestLength()) };
    switch (algorithm) {
        .sha256 => s.bytes[0..32].* = hash.Sha256.hash(""),
        .sha384 => s.bytes[0..48].* = hash.Sha384.hash(""),
    }
    return s;
}

/// The next generation of a traffic secret, for KeyUpdate (§7.2).
pub fn nextTrafficSecret(algorithm: hash.Algorithm, secret: *const Secret) Secret {
    var s: Secret = .{ .bytes = undefined, .len = secret.len };
    hkdf.expandLabel(algorithm, secret.slice(), "traffic upd", "", s.bytes[0..secret.len]);
    return s;
}

/// The verify_data of a Finished message (§4.5.3) for the side whose
/// traffic secret this is.
pub fn verifyData(algorithm: hash.Algorithm, traffic_secret: *const Secret, transcript_hash: []const u8, out: *[hash.max_digest_length]u8) []const u8 {
    var finished_key: Secret = .{ .bytes = undefined, .len = traffic_secret.len };
    defer finished_key.wipe();
    hkdf.expandLabel(algorithm, traffic_secret.slice(), "finished", "", finished_key.bytes[0..finished_key.len]);
    return hash.hmac(algorithm, finished_key.slice(), transcript_hash, out);
}

const testing = std.testing;
const data13 = @import("../testdata/tls13.zig");

test "the example connection's key schedule" {
    var transcript = Transcript.init();
    transcript.update(data13.client_hello[5..]);
    transcript.update(data13.server_hello[5..]);
    transcript.select(.sha384);
    var hbuf: [hash.max_digest_length]u8 = undefined;
    const hello_hash = transcript.digest(&hbuf);

    var ks = KeySchedule.init(.sha384);
    defer ks.deinit();
    ks.deriveHandshakeSecret(&data13.shared_key);
    const c_hs = ks.trafficSecret(.client_handshake, hello_hash);
    const s_hs = ks.trafficSecret(.server_handshake, hello_hash);
    var key: [32]u8 = undefined;
    var iv: [12]u8 = undefined;
    hkdf.expandLabel(.sha384, s_hs.slice(), "key", "", &key);
    hkdf.expandLabel(.sha384, s_hs.slice(), "iv", "", &iv);
    try testing.expectEqualSlices(u8, &data13.server_handshake_key, &key);
    try testing.expectEqualSlices(u8, &data13.server_handshake_iv, &iv);

    ks.deriveMasterSecret();
    const c_ap = ks.trafficSecret(.client_application, &data13.handshake_hash);
    hkdf.expandLabel(.sha384, c_ap.slice(), "key", "", &key);
    hkdf.expandLabel(.sha384, c_ap.slice(), "iv", "", &iv);
    try testing.expectEqualSlices(u8, &data13.client_application_key, &key);
    try testing.expectEqualSlices(u8, &data13.client_application_iv, &iv);

    var vbuf: [hash.max_digest_length]u8 = undefined;
    try testing.expectEqualSlices(u8, &data13.client_finished_verify_data, verifyData(.sha384, &c_hs, &data13.handshake_hash, &vbuf));
}

test "transcript selection and message_hash replacement" {
    var t = Transcript.init();
    t.update("ClientHello");
    t.select(.sha256);
    var buf: [hash.max_digest_length]u8 = undefined;
    try testing.expectEqualSlices(u8, &hash.Sha256.hash("ClientHello"), t.digest(&buf));

    t.replaceWithMessageHash();
    var expected = hash.Sha256.init();
    expected.update(&[_]u8{ 254, 0, 0, 32 });
    expected.update(&hash.Sha256.hash("ClientHello"));
    try testing.expectEqualSlices(u8, &expected.peek(), t.digest(&buf));
    t.update("ServerHello");
    expected.update("ServerHello");
    try testing.expectEqualSlices(u8, &expected.final(), t.digest(&buf));

    var t2 = Transcript.init();
    t2.update("x");
    t2.select(.sha384);
    try testing.expectEqualSlices(u8, &hash.Sha384.hash("x"), t2.digest(&buf));
}

test "key update derives a different secret of the same length" {
    const ks = KeySchedule.init(.sha256);
    const s = ks.trafficSecret(.client_application, &hash.Sha256.hash("t"));
    const n = nextTrafficSecret(.sha256, &s);
    try testing.expectEqual(32, n.len);
    try testing.expect(!std.mem.eql(u8, s.slice(), n.slice()));
    try testing.expect(!std.mem.eql(u8, n.slice(), nextTrafficSecret(.sha256, &n).slice()));
}
