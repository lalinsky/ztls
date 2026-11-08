//! HKDF (RFC 5869) and the TLS 1.3 key schedule primitives built on it
//! (RFC 9846 §7.1).

const std = @import("std");
const assert = std.debug.assert;
const c = @import("c");
const hash = @import("hash.zig");

pub const max_length = hash.max_digest_length;

/// HKDF-Extract. Returns the PRK, `algorithm.digestLength()` bytes of `out`.
pub fn extract(algorithm: hash.Algorithm, salt: []const u8, ikm: []const u8, out: *[max_length]u8) []u8 {
    var out_len: usize = 0;
    const ok = c.HKDF_extract(out, &out_len, algorithm.md(), ikm.ptr, ikm.len, salt.ptr, salt.len);
    assert(ok == 1 and out_len == algorithm.digestLength());
    return out[0..out_len];
}

/// HKDF-Expand, filling all of `out`.
pub fn expand(algorithm: hash.Algorithm, prk: []const u8, info: []const u8, out: []u8) void {
    assert(out.len <= 255 * algorithm.digestLength());
    const ok = c.HKDF_expand(out.ptr, out.len, algorithm.md(), prk.ptr, prk.len, info.ptr, info.len);
    assert(ok == 1);
}

pub const max_label_length = 32;

/// HKDF-Expand-Label, filling all of `out`.
pub fn expandLabel(algorithm: hash.Algorithm, secret: []const u8, label: []const u8, context: []const u8, out: []u8) void {
    const prefix = "tls13 ";
    assert(label.len <= max_label_length);
    assert(context.len <= max_length);
    assert(out.len <= std.math.maxInt(u16));

    // struct { uint16 length; opaque label<7..255>; opaque context<0..255>; }
    var info: [2 + 1 + prefix.len + max_label_length + 1 + max_length]u8 = undefined;
    var n: usize = 0;
    std.mem.writeInt(u16, info[n..][0..2], @intCast(out.len), .big);
    n += 2;
    info[n] = @intCast(prefix.len + label.len);
    n += 1;
    @memcpy(info[n..][0..prefix.len], prefix);
    n += prefix.len;
    @memcpy(info[n..][0..label.len], label);
    n += label.len;
    info[n] = @intCast(context.len);
    n += 1;
    @memcpy(info[n..][0..context.len], context);
    n += context.len;

    expand(algorithm, secret, info[0..n], out);
}

/// Derive-Secret: Expand-Label to a digest-sized secret, with a transcript
/// hash as the context. Returns the used part of `out`.
pub fn deriveSecret(algorithm: hash.Algorithm, secret: []const u8, label: []const u8, transcript_hash: []const u8, out: *[max_length]u8) []u8 {
    const n = algorithm.digestLength();
    expandLabel(algorithm, secret, label, transcript_hash, out[0..n]);
    return out[0..n];
}

const testing = std.testing;
const data13 = @import("../testdata/tls13.zig");

test "RFC 5869 test case 1" {
    const ikm: [22]u8 = @splat(0x0b);
    const salt = hex("000102030405060708090a0b0c");
    const info = hex("f0f1f2f3f4f5f6f7f8f9");
    var prk_buf: [max_length]u8 = undefined;
    const prk = extract(.sha256, &salt, &ikm, &prk_buf);
    try testing.expectEqualSlices(u8, &hex("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"), prk);
    var okm: [42]u8 = undefined;
    expand(.sha256, prk, &info, &okm);
    try testing.expectEqualSlices(u8, &hex("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"), &okm);
}

test "TLS 1.3 key schedule against the example connection" {
    // The example suite is AES_256_GCM_SHA384 with x25519; the handshake
    // messages are the records' payloads without the 5-byte record headers.
    const alg: hash.Algorithm = .sha384;
    var transcript = hash.Sha384.init();
    transcript.update(data13.client_hello[5..]);
    transcript.update(data13.server_hello[5..]);
    const hello_hash = transcript.peek();
    const empty_hash = hash.Sha384.hash("");

    const zeros: [48]u8 = @splat(0);
    var early_buf: [max_length]u8 = undefined;
    const early_secret = extract(alg, &zeros, &zeros, &early_buf);
    var derived_buf: [max_length]u8 = undefined;
    const derived = deriveSecret(alg, early_secret, "derived", &empty_hash, &derived_buf);
    var hs_buf: [max_length]u8 = undefined;
    const handshake_secret = extract(alg, derived, &data13.shared_key, &hs_buf);

    var s_hs_buf: [max_length]u8 = undefined;
    const s_hs_traffic = deriveSecret(alg, handshake_secret, "s hs traffic", &hello_hash, &s_hs_buf);
    var c_hs_buf: [max_length]u8 = undefined;
    const c_hs_traffic = deriveSecret(alg, handshake_secret, "c hs traffic", &hello_hash, &c_hs_buf);

    var key: [32]u8 = undefined;
    var iv: [12]u8 = undefined;
    expandLabel(alg, s_hs_traffic, "key", "", &key);
    expandLabel(alg, s_hs_traffic, "iv", "", &iv);
    try testing.expectEqualSlices(u8, &data13.server_handshake_key, &key);
    try testing.expectEqualSlices(u8, &data13.server_handshake_iv, &iv);
    expandLabel(alg, c_hs_traffic, "key", "", &key);
    expandLabel(alg, c_hs_traffic, "iv", "", &iv);
    try testing.expectEqualSlices(u8, &data13.client_handshake_key, &key);
    try testing.expectEqualSlices(u8, &data13.client_handshake_iv, &iv);

    // Application keys, from the transcript through the server Finished.
    const derived2 = deriveSecret(alg, handshake_secret, "derived", &empty_hash, &derived_buf);
    var master_buf: [max_length]u8 = undefined;
    const master_secret = extract(alg, derived2, &zeros, &master_buf);
    var s_ap_buf: [max_length]u8 = undefined;
    const s_ap_traffic = deriveSecret(alg, master_secret, "s ap traffic", &data13.handshake_hash, &s_ap_buf);
    expandLabel(alg, s_ap_traffic, "key", "", &key);
    expandLabel(alg, s_ap_traffic, "iv", "", &iv);
    try testing.expectEqualSlices(u8, &data13.server_application_key, &key);
    try testing.expectEqualSlices(u8, &data13.server_application_iv, &iv);
    var c_ap_buf: [max_length]u8 = undefined;
    const c_ap_traffic = deriveSecret(alg, master_secret, "c ap traffic", &data13.handshake_hash, &c_ap_buf);
    expandLabel(alg, c_ap_traffic, "key", "", &key);
    expandLabel(alg, c_ap_traffic, "iv", "", &iv);
    try testing.expectEqualSlices(u8, &data13.client_application_key, &key);
    try testing.expectEqualSlices(u8, &data13.client_application_iv, &iv);

    // Client Finished: HMAC(finished_key, transcript hash).
    var finished_key: [48]u8 = undefined;
    expandLabel(alg, c_hs_traffic, "finished", "", &finished_key);
    var mac_buf: [hash.max_digest_length]u8 = undefined;
    const verify_data = hash.hmac(alg, &finished_key, &data13.handshake_hash, &mac_buf);
    try testing.expectEqualSlices(u8, &data13.client_finished_verify_data, verify_data);
}

fn hex(comptime s: []const u8) [s.len / 2]u8 {
    var out: [s.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, s) catch unreachable;
    return out;
}
