//! The record-protection AEADs, keyed once per direction. AWS-LC's contexts
//! are immutable after `init`, so one context serves any number of seals or
//! opens, concurrently if need be.
//!
//! Each call encrypts or decrypts one record in one pass, either exactly in
//! place or between two disjoint buffers. A shifted overlap is forbidden
//! (AWS-LC checks it and fails), and never needed.

const std = @import("std");
const assert = std.debug.assert;
const c = @import("c");
const err = @import("err.zig");

/// Only AEADs whose AWS-LC state is plain inline data (an AES key schedule
/// and GHASH key, or a ChaCha key) belong here: `Context` relies on that to
/// be movable and to wipe its key itself. AES-GCM-SIV, for one, is not.
pub const Algorithm = enum {
    aes_128_gcm,
    aes_256_gcm,
    chacha20_poly1305,

    pub fn keyLength(a: Algorithm) usize {
        return switch (a) {
            .aes_128_gcm => 16,
            .aes_256_gcm, .chacha20_poly1305 => 32,
        };
    }

    fn evp(a: Algorithm) *const c.EVP_AEAD {
        // The plain AEADs, not EVP_aead_*_tls13: those track the nonce
        // sequence inside the context, which the record layer does itself.
        return switch (a) {
            .aes_128_gcm => c.EVP_aead_aes_128_gcm().?,
            .aes_256_gcm => c.EVP_aead_aes_256_gcm().?,
            .chacha20_poly1305 => c.EVP_aead_chacha20_poly1305().?,
        };
    }
};

pub const max_key_length = 32;
pub const nonce_length = 12;
pub const tag_length = 16;

pub const Nonce = [nonce_length]u8;
pub const Tag = [tag_length]u8;

/// A keyed context. Plain data with no pointers into itself, so it may be
/// moved or copied; each copy then holds its own key material and needs its
/// own `deinit`, which wipes it (AWS-LC's cleanup does not for these AEADs).
pub const Context = struct {
    ctx: c.EVP_AEAD_CTX,

    pub fn init(algorithm: Algorithm, key: []const u8) err.Error!Context {
        assert(key.len == algorithm.keyLength());
        var self: Context = undefined;
        if (c.EVP_AEAD_CTX_init(&self.ctx, algorithm.evp(), key.ptr, key.len, tag_length, null) != 1) return err.fail();
        return self;
    }

    pub fn deinit(self: *Context) void {
        c.EVP_AEAD_CTX_cleanup(&self.ctx);
        std.crypto.secureZero(u8, std.mem.asBytes(&self.ctx));
        self.* = undefined;
    }

    /// Encrypts `plaintext` to `out` (the same length) and writes the tag.
    /// `out` is either exactly `plaintext` or disjoint from it.
    pub fn seal(self: *const Context, nonce: *const Nonce, ad: []const u8, plaintext: []const u8, out: []u8, tag: *Tag) void {
        assert(out.len == plaintext.len);
        assert(samePlaceOrDisjoint(plaintext, out));
        assert(disjoint(tag, plaintext) and disjoint(tag, out));
        var tag_len: usize = 0;
        const ok = c.EVP_AEAD_CTX_seal_scatter(&self.ctx, out.ptr, tag, &tag_len, tag_length, nonce, nonce_length, plaintext.ptr, plaintext.len, null, 0, ad.ptr, ad.len);
        // Fails only on misuse (nonce or length limits), which the record
        // layer rules out.
        assert(ok == 1 and tag_len == tag_length);
    }

    /// Checks the tag and decrypts `ciphertext` to `out` (the same length).
    /// `out` is either exactly `ciphertext` or disjoint from it. On failure
    /// nothing can be said about `out`.
    pub fn open(self: *const Context, nonce: *const Nonce, ad: []const u8, ciphertext: []const u8, tag: *const Tag, out: []u8) error{AuthenticationFailed}!void {
        assert(out.len == ciphertext.len);
        assert(samePlaceOrDisjoint(ciphertext, out));
        assert(disjoint(tag, ciphertext) and disjoint(tag, out));
        if (c.EVP_AEAD_CTX_open_gather(&self.ctx, out.ptr, nonce, nonce_length, ciphertext.ptr, ciphertext.len, tag, tag_length, ad.ptr, ad.len) != 1) {
            _ = err.take();
            return error.AuthenticationFailed;
        }
    }
};

fn samePlaceOrDisjoint(a: []const u8, b: []const u8) bool {
    return a.ptr == b.ptr or disjoint(a, b);
}

fn disjoint(a: []const u8, b: []const u8) bool {
    const a_start = @intFromPtr(a.ptr);
    const b_start = @intFromPtr(b.ptr);
    return a_start + a.len <= b_start or b_start + b.len <= a_start;
}

const testing = std.testing;
const data13 = @import("../testdata/tls13.zig");

test "round trips, in place and out of place" {
    for ([_]Algorithm{ .aes_128_gcm, .aes_256_gcm, .chacha20_poly1305 }) |alg| {
        const key: [max_key_length]u8 = @splat(0x42);
        var ctx = try Context.init(alg, key[0..alg.keyLength()]);
        defer ctx.deinit();
        const nonce: Nonce = @splat(7);
        const message = "attack at dawn";

        var out_of_place: [message.len]u8 = undefined;
        var tag: Tag = undefined;
        ctx.seal(&nonce, "ad", message, &out_of_place, &tag);
        try testing.expect(!std.mem.eql(u8, message, &out_of_place));

        var in_place: [message.len]u8 = message.*;
        var tag2: Tag = undefined;
        ctx.seal(&nonce, "ad", &in_place, &in_place, &tag2);
        try testing.expectEqualSlices(u8, &out_of_place, &in_place);
        try testing.expectEqualSlices(u8, &tag, &tag2);

        try ctx.open(&nonce, "ad", &in_place, &tag, &in_place);
        try testing.expectEqualSlices(u8, message, &in_place);

        var opened: [message.len]u8 = undefined;
        try ctx.open(&nonce, "ad", &out_of_place, &tag, &opened);
        try testing.expectEqualSlices(u8, message, &opened);

        tag[0] ^= 1;
        try testing.expectError(error.AuthenticationFailed, ctx.open(&nonce, "ad", &out_of_place, &tag, &opened));
        tag[0] ^= 1;
        try testing.expectError(error.AuthenticationFailed, ctx.open(&nonce, "da", &out_of_place, &tag, &opened));

        // A moved context works the same.
        const copy = ctx;
        try copy.open(&nonce, "ad", &out_of_place, &tag, &opened);
        try testing.expectEqualSlices(u8, message, &opened);
    }
}

test "empty plaintext" {
    const key: [16]u8 = @splat(1);
    var ctx = try Context.init(.aes_128_gcm, &key);
    defer ctx.deinit();
    const nonce: Nonce = @splat(0);
    var tag: Tag = undefined;
    ctx.seal(&nonce, "", "", &.{}, &tag);
    try ctx.open(&nonce, "", "", &tag, &.{});
    tag[15] ^= 1;
    try testing.expectError(error.AuthenticationFailed, ctx.open(&nonce, "", "", &tag, &.{}));
}

/// Opens one TLS 1.3 record (header + ciphertext + tag) with sequence
/// number `seq`, returning the inner plaintext (content type last).
fn openRecord(ctx: *const Context, iv: *const Nonce, seq: u64, record: []const u8, out: []u8) ![]u8 {
    const header = record[0..5];
    const body = record[5..];
    const ciphertext = body[0 .. body.len - tag_length];
    const tag = body[body.len - tag_length ..][0..tag_length];
    var nonce = iv.*;
    var seq_bytes: [8]u8 = undefined;
    std.mem.writeInt(u64, &seq_bytes, seq, .big);
    for (nonce[4..], seq_bytes) |*n, s| n.* ^= s;
    try ctx.open(&nonce, header, ciphertext, tag, out[0..ciphertext.len]);
    return out[0..ciphertext.len];
}

test "records from the example connection" {
    var server_hs = try Context.init(.aes_256_gcm, &data13.server_handshake_key);
    defer server_hs.deinit();
    var buf: [1024]u8 = undefined;
    const ee = try openRecord(&server_hs, &data13.server_handshake_iv, 0, &data13.server_encrypted_extensions_wrapped, &buf);
    try testing.expectEqualSlices(u8, &(data13.server_encrypted_extensions ++ [_]u8{0x16}), ee);
    const cert = try openRecord(&server_hs, &data13.server_handshake_iv, 1, &data13.server_certificate_wrapped, &buf);
    try testing.expectEqualSlices(u8, &(data13.server_certificate ++ [_]u8{0x16}), cert);

    var client_ap = try Context.init(.aes_256_gcm, &data13.client_application_key);
    defer client_ap.deinit();
    const ping = try openRecord(&client_ap, &data13.client_application_iv, 0, &data13.client_ping_wrapped, &buf);
    try testing.expectEqualSlices(u8, "ping" ++ [_]u8{0x17}, ping);

    // And sealing reproduces the record byte for byte.
    const wrapped = data13.client_ping_wrapped;
    var sealed: [wrapped.len - 5 - tag_length]u8 = undefined;
    var tag: Tag = undefined;
    client_ap.seal(&data13.client_application_iv, wrapped[0..5], ping, &sealed, &tag);
    try testing.expectEqualSlices(u8, wrapped[5 .. wrapped.len - tag_length], &sealed);
    try testing.expectEqualSlices(u8, wrapped[wrapped.len - tag_length ..], &tag);
}
