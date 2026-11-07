//! What the client and server handshakes share: key shares, handshake
//! messages read out of records and written into them, the key schedule
//! steps, and the Certificate, CertificateVerify and Finished messages.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const proto = @import("protocol.zig");
const codec = @import("codec.zig");
const cipher = @import("cipher.zig");
const config = @import("config.zig");
const crypto = @import("crypto.zig");
const kx = crypto.kx;
const sig = crypto.sig;
const x509 = crypto.x509;
const key_schedule = @import("key_schedule.zig");
const Secret = key_schedule.Secret;
const Connection = @import("connection.zig").Connection;

const log = std.log.scoped(.ztls);

/// What a handshake can fail with. `EndOfStream` is the peer going away
/// before it was done; `ReadFailed`/`WriteFailed` are the transport's,
/// whose own error says why.
pub const Error = proto.LocalError || proto.Alert.Error || error{
    ReadFailed,
    WriteFailed,
    EndOfStream,
    OutOfMemory,
};

/// The ServerHello.random that makes it a HelloRetryRequest (§4.1.3).
pub const hello_retry_request_random = [32]u8{
    0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11, 0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
    0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E, 0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C,
};

/// What we put in signature_algorithms, in preference order. The
/// rsa_pkcs1 ones are for certificate signatures only, which X.509
/// verification checks; they never sign a CertificateVerify.
pub const signature_algorithms = [_]proto.SignatureScheme{
    .ecdsa_secp256r1_sha256,
    .ecdsa_secp384r1_sha384,
    .ecdsa_secp521r1_sha512,
    .ed25519,
    .rsa_pss_rsae_sha256,
    .rsa_pss_rsae_sha384,
    .rsa_pss_rsae_sha512,
    .rsa_pkcs1_sha256,
    .rsa_pkcs1_sha384,
    .rsa_pkcs1_sha512,
};

/// The algorithm a scheme stands for in a CertificateVerify, or null for
/// one that may not sign it.
pub fn schemeAlgorithm(scheme: proto.SignatureScheme) ?sig.Algorithm {
    return switch (scheme) {
        .ecdsa_secp256r1_sha256 => .ecdsa_p256_sha256,
        .ecdsa_secp384r1_sha384 => .ecdsa_p384_sha384,
        .ecdsa_secp521r1_sha512 => .ecdsa_p521_sha512,
        .ed25519 => .ed25519,
        .rsa_pss_rsae_sha256 => .rsa_pss_sha256,
        .rsa_pss_rsae_sha384 => .rsa_pss_sha384,
        .rsa_pss_rsae_sha512 => .rsa_pss_sha512,
        else => null,
    };
}

/// The scheme to sign a CertificateVerify with: our most preferred one
/// that the peer offered and that suits the key.
pub fn selectScheme(key_type: sig.KeyType, offered: []const proto.SignatureScheme) ?proto.SignatureScheme {
    for (signature_algorithms) |scheme| {
        const algorithm = schemeAlgorithm(scheme) orelse continue;
        if (!algorithm.suits(key_type)) continue;
        if (std.mem.indexOfScalar(proto.SignatureScheme, offered, scheme) != null) return scheme;
    }
    return null;
}

pub fn groupSupported(group: proto.NamedGroup) bool {
    return switch (group) {
        .x25519, .secp256r1, .secp384r1, .x25519_ml_kem768 => true,
        else => false,
    };
}

/// The key shares a side generates, one per group.
pub const KeyShares = struct {
    x25519: ?kx.X25519 = null,
    p256: ?kx.Ecdh = null,
    p384: ?kx.Ecdh = null,
    hybrid: ?kx.X25519MlKem768 = null,

    pub const max_share_len = kx.X25519MlKem768.client_share_length;
    pub const max_secret_len = kx.X25519MlKem768.shared_secret_length;

    /// Fails with `TlsInternalError` on a group ztls does not implement.
    pub fn generate(groups: []const proto.NamedGroup) Error!KeyShares {
        var shares: KeyShares = .{};
        errdefer shares.deinit();
        for (groups) |group| switch (group) {
            .x25519 => shares.x25519 = kx.X25519.generate(),
            .secp256r1 => shares.p256 = kx.Ecdh.generate(.p256) catch return error.TlsInternalError,
            .secp384r1 => shares.p384 = kx.Ecdh.generate(.p384) catch return error.TlsInternalError,
            .x25519_ml_kem768 => shares.hybrid = kx.X25519MlKem768.generate() catch return error.TlsInternalError,
            else => return error.TlsInternalError,
        };
        return shares;
    }

    pub fn deinit(shares: *KeyShares) void {
        if (shares.x25519) |*k| k.deinit();
        if (shares.p256) |*k| k.deinit();
        if (shares.p384) |*k| k.deinit();
        if (shares.hybrid) |*k| k.deinit();
        shares.* = .{};
    }

    pub fn has(shares: *const KeyShares, group: proto.NamedGroup) bool {
        return switch (group) {
            .x25519 => shares.x25519 != null,
            .secp256r1 => shares.p256 != null,
            .secp384r1 => shares.p384 != null,
            .x25519_ml_kem768 => shares.hybrid != null,
            else => false,
        };
    }

    /// The share to send for `group`, which must have been generated.
    pub fn publicShare(shares: *const KeyShares, group: proto.NamedGroup, out: *[max_share_len]u8) []const u8 {
        return switch (group) {
            .x25519 => {
                out[0..32].* = shares.x25519.?.public;
                return out[0..32];
            },
            .secp256r1 => shares.p256.?.publicKey(out[0..kx.Ecdh.max_public_length]),
            .secp384r1 => shares.p384.?.publicKey(out[0..kx.Ecdh.max_public_length]),
            .x25519_ml_kem768 => {
                out[0..max_share_len].* = shares.hybrid.?.clientShare();
                return out[0..max_share_len];
            },
            else => unreachable,
        };
    }

    /// The client's side: the secret from the server's share.
    pub fn sharedSecret(shares: *const KeyShares, group: proto.NamedGroup, peer: []const u8, out: *[max_secret_len]u8) Error![]const u8 {
        switch (group) {
            .x25519 => {
                if (peer.len != kx.X25519.public_length) return error.TlsIllegalParameter;
                out[0..32].* = shares.x25519.?.sharedSecret(peer[0..32]) catch return error.TlsIllegalParameter;
                return out[0..32];
            },
            .secp256r1 => return shares.p256.?.sharedSecret(peer, out[0..kx.Ecdh.max_shared_length]) catch |err| switch (err) {
                error.InvalidPublicKey => error.TlsIllegalParameter,
                error.CryptoFailed => error.TlsInternalError,
            },
            .secp384r1 => return shares.p384.?.sharedSecret(peer, out[0..kx.Ecdh.max_shared_length]) catch |err| switch (err) {
                error.InvalidPublicKey => error.TlsIllegalParameter,
                error.CryptoFailed => error.TlsInternalError,
            },
            .x25519_ml_kem768 => {
                if (peer.len != kx.X25519MlKem768.server_share_length) return error.TlsIllegalParameter;
                out.* = shares.hybrid.?.finish(peer[0..kx.X25519MlKem768.server_share_length]) catch |err| switch (err) {
                    error.InvalidPublicKey => return error.TlsIllegalParameter,
                    error.CryptoFailed => return error.TlsInternalError,
                };
                return out;
            },
            else => return error.TlsIllegalParameter,
        }
    }

    pub const Response = struct {
        share: []const u8,
        secret: []const u8,
    };

    /// The server's side, in one step: from the client's share, the share
    /// to send back and the secret. No state is kept.
    pub fn respond(group: proto.NamedGroup, client_share: []const u8, out_share: *[max_share_len]u8, out_secret: *[max_secret_len]u8) Error!Response {
        switch (group) {
            .x25519 => {
                if (client_share.len != kx.X25519.public_length) return error.TlsIllegalParameter;
                var ours = kx.X25519.generate();
                defer ours.deinit();
                out_secret[0..32].* = ours.sharedSecret(client_share[0..32]) catch return error.TlsIllegalParameter;
                out_share[0..32].* = ours.public;
                return .{ .share = out_share[0..32], .secret = out_secret[0..32] };
            },
            .secp256r1, .secp384r1 => {
                var ours = kx.Ecdh.generate(if (group == .secp256r1) .p256 else .p384) catch return error.TlsInternalError;
                defer ours.deinit();
                const secret = ours.sharedSecret(client_share, out_secret[0..kx.Ecdh.max_shared_length]) catch |err| switch (err) {
                    error.InvalidPublicKey => return error.TlsIllegalParameter,
                    error.CryptoFailed => return error.TlsInternalError,
                };
                return .{ .share = ours.publicKey(out_share[0..kx.Ecdh.max_public_length]), .secret = secret };
            },
            .x25519_ml_kem768 => {
                if (client_share.len != kx.X25519MlKem768.client_share_length) return error.TlsIllegalParameter;
                out_secret.* = kx.X25519MlKem768.respond(client_share[0..kx.X25519MlKem768.client_share_length], out_share[0..kx.X25519MlKem768.server_share_length]) catch |err| switch (err) {
                    error.InvalidPublicKey => return error.TlsIllegalParameter,
                    error.CryptoFailed => return error.TlsInternalError,
                };
                return .{ .share = out_share[0..kx.X25519MlKem768.server_share_length], .secret = out_secret };
            },
            else => return error.TlsIllegalParameter,
        }
    }
};

/// The peer's certificate chain as received, with the leaf's key.
pub const PeerCertificate = struct {
    chain: [config.CertKeyPair.max_chain_len]x509.Certificate = undefined,
    len: usize = 0,
    public_key: sig.PublicKey,

    pub fn deinit(peer: *PeerCertificate) void {
        for (peer.chain[0..peer.len]) |*cert| cert.deinit();
        peer.public_key.deinit();
        peer.* = undefined;
    }
};

/// One handshake message, reassembled.
pub const Message = struct {
    handshake_type: proto.HandshakeType,
    /// Without the 4-byte header.
    body: []const u8,
    /// With it: what the transcript hashes.
    raw: []const u8,
};

pub const Handshake = struct {
    conn: *Connection,
    allocator: Allocator,
    max_message_len: usize,
    transcript: key_schedule.Transcript,
    schedule: ?key_schedule.KeySchedule = null,
    suite: proto.CipherSuite = undefined,
    /// Received handshake bytes not yet taken as messages.
    inbox: std.ArrayList(u8) = .empty,
    inbox_pos: usize = 0,

    pub fn init(conn: *Connection, allocator: Allocator, max_message_len: usize) Handshake {
        return .{
            .conn = conn,
            .allocator = allocator,
            .max_message_len = max_message_len,
            .transcript = .init(),
        };
    }

    pub fn deinit(h: *Handshake) void {
        h.inbox.deinit(h.allocator);
        if (h.schedule) |*s| s.deinit();
        h.* = undefined;
    }

    // Receiving

    /// The next handshake message from the peer, whole, reassembled across
    /// records if need be. It lives until the next call. The caller hashes
    /// it into the transcript (`hashMessage`) once it is dealt with.
    pub fn nextMessage(h: *Handshake) Error!Message {
        while (true) {
            const pending = h.inbox.items[h.inbox_pos..];
            if (pending.len >= 4) {
                const len = std.mem.readInt(u24, pending[1..4], .big);
                // Bigger than we take; the peer's doing, so it hears so.
                if (len > h.max_message_len) return error.TlsIllegalParameter;
                if (pending.len >= 4 + len) {
                    const raw = pending[0 .. 4 + len];
                    h.inbox_pos += raw.len;
                    return .{ .handshake_type = @enumFromInt(raw[0]), .body = raw[4..], .raw = raw };
                }
            }
            try h.readHandshakeRecord();
        }
    }

    /// Appends the next handshake record's payload to the inbox. Alerts
    /// end the handshake; application data is out of place.
    fn readHandshakeRecord(h: *Handshake) Error!void {
        if (h.inbox_pos == h.inbox.items.len) {
            h.inbox.clearRetainingCapacity();
            h.inbox_pos = 0;
        } else if (h.inbox_pos > 0) {
            const kept = h.inbox.items.len - h.inbox_pos;
            std.mem.copyForwards(u8, h.inbox.items[0..kept], h.inbox.items[h.inbox_pos..]);
            h.inbox.shrinkRetainingCapacity(kept);
            h.inbox_pos = 0;
        }
        while (true) {
            const record = h.conn.readRecord(null) catch |err| switch (err) {
                error.EndOfStream => return error.EndOfStream,
                error.ReadFailed => return error.ReadFailed,
                else => |e| return e,
            };
            switch (record.content_type) {
                .handshake => {
                    if (record.payload.len == 0) return error.TlsUnexpectedMessage;
                    if (h.inbox.items.len + record.payload.len > h.max_message_len + 4 + cipher.max_plaintext_len) return error.TlsIllegalParameter;
                    try h.inbox.appendSlice(h.allocator, record.payload);
                    return;
                },
                .alert => {
                    if (record.payload.len != 2) return error.TlsDecodeError;
                    const alert = proto.Alert.decode(record.payload[0..2]);
                    if (alert.toError()) |err| return err;
                    // close_notify during the handshake: the peer gave up.
                    if (alert == .close_notify) return error.EndOfStream;
                    continue; // user_canceled, with close_notify to follow
                },
                else => return error.TlsUnexpectedMessage,
            }
        }
    }

    /// Fails unless the message is of the expected type.
    pub fn expect(h: *Handshake, message: Message, handshake_type: proto.HandshakeType) Error!void {
        _ = h;
        if (message.handshake_type != handshake_type) return error.TlsUnexpectedMessage;
    }

    pub fn hashMessage(h: *Handshake, message: Message) void {
        h.transcript.update(message.raw);
    }

    // Sending

    /// Writes handshake message bytes into records in `output`, sealed
    /// when there are keys, hashing them into the transcript as it goes.
    /// A message may span records, and a record may hold several.
    pub const MessageWriter = struct {
        h: *Handshake,
        /// The plaintext of the record being filled, in `output`.
        window: []u8,
        len: usize = 0,

        pub fn write(w: *MessageWriter, bytes: []const u8) Error!void {
            w.h.transcript.update(bytes);
            var rest = bytes;
            while (rest.len > 0) {
                if (w.len == w.window.len) try w.flushRecord();
                const n = @min(rest.len, w.window.len - w.len);
                @memcpy(w.window[w.len..][0..n], rest[0..n]);
                w.len += n;
                rest = rest[n..];
            }
        }

        pub fn int(w: *MessageWriter, comptime T: type, value: anytype) Error!void {
            var buf: [@divExact(@typeInfo(T).int.bits, 8)]u8 = undefined;
            std.mem.writeInt(T, &buf, @intCast(value), .big);
            try w.write(&buf);
        }

        /// Puts the partial record out. Must end every message sequence.
        pub fn finish(w: *MessageWriter) Error!void {
            if (w.len > 0) try w.flushRecord();
        }

        fn flushRecord(w: *MessageWriter) Error!void {
            const c = w.h.conn;
            const unused = c.output.unusedCapacitySlice();
            assert(w.window.ptr == unused.ptr + cipher.header_len);
            const record_len = if (c.write.keys) |*keys| blk: {
                keys.seal(unused, .handshake, w.len) catch return error.TlsInternalError;
                break :blk cipher.Keys.sealedLen(w.len);
            } else blk: {
                unused[0] = @intFromEnum(proto.ContentType.handshake);
                std.mem.writeInt(u16, unused[1..3], @intFromEnum(proto.Version.tls_1_2), .big);
                std.mem.writeInt(u16, unused[3..5], @intCast(w.len), .big);
                break :blk cipher.header_len + w.len;
            };
            c.output.advance(record_len);
            if (c.output.unusedCapacityLen() < cipher.max_sealed_record_len) {
                c.output.flush() catch return error.WriteFailed;
            }
            w.window = recordWindow(c);
            w.len = 0;
        }
    };

    /// Where the next record's plaintext goes in `output`.
    fn recordWindow(c: *Connection) []u8 {
        const unused = c.output.unusedCapacitySlice();
        const overhead: usize = if (c.write.keys != null) cipher.header_len + cipher.seal_overhead else cipher.header_len;
        assert(unused.len > overhead);
        return unused[cipher.header_len..][0..@min(cipher.max_plaintext_len, unused.len - overhead)];
    }

    pub fn messageWriter(h: *Handshake) Error!MessageWriter {
        if (h.conn.output.unusedCapacityLen() < cipher.max_sealed_record_len) {
            h.conn.output.flush() catch return error.WriteFailed;
        }
        return .{ .h = h, .window = recordWindow(h.conn) };
    }

    /// Writes one whole message, header included.
    pub fn writeMessage(h: *Handshake, raw: []const u8) Error!void {
        var w = try h.messageWriter();
        try w.write(raw);
        try w.finish();
    }

    pub fn flush(h: *Handshake) Error!void {
        h.conn.output.flush() catch return error.WriteFailed;
    }

    /// Tells the peer why the handshake failed, when that is something we
    /// found: nothing goes out for its own alerts or for a transport that
    /// failed. Never fails further.
    pub fn sendAlert(h: *Handshake, err: anyerror) void {
        const alert = proto.Alert.forLocalError(err) orelse return;
        h.conn.writeAlert(alert) catch return;
        h.conn.output.flush() catch return;
    }

    // Key schedule

    /// Fixes the suite: the transcript hash and the schedule follow it.
    pub fn setSuite(h: *Handshake, suite: proto.CipherSuite) void {
        assert(h.schedule == null);
        const hash_algorithm = cipher.suiteHash(suite).?;
        h.suite = suite;
        h.transcript.select(hash_algorithm);
        h.schedule = key_schedule.KeySchedule.init(hash_algorithm);
    }

    pub fn transcriptHash(h: *const Handshake, out: *[crypto.hash.max_digest_length]u8) []const u8 {
        return h.transcript.digest(out);
    }

    pub const TrafficSecrets = struct {
        client: Secret,
        server: Secret,

        pub fn wipe(s: *TrafficSecrets) void {
            s.client.wipe();
            s.server.wipe();
        }
    };

    /// After the ServerHello is hashed: the handshake traffic secrets.
    pub fn deriveHandshakeSecrets(h: *Handshake, shared_secret: []const u8) TrafficSecrets {
        h.schedule.?.deriveHandshakeSecret(shared_secret);
        var buf: [crypto.hash.max_digest_length]u8 = undefined;
        const hash = h.transcriptHash(&buf);
        return .{
            .client = h.schedule.?.trafficSecret(.client_handshake, hash),
            .server = h.schedule.?.trafficSecret(.server_handshake, hash),
        };
    }

    /// After the server Finished is hashed: the application traffic
    /// secrets.
    pub fn deriveApplicationSecrets(h: *Handshake) TrafficSecrets {
        h.schedule.?.deriveMasterSecret();
        var buf: [crypto.hash.max_digest_length]u8 = undefined;
        const hash = h.transcriptHash(&buf);
        return .{
            .client = h.schedule.?.trafficSecret(.client_application, hash),
            .server = h.schedule.?.trafficSecret(.server_application, hash),
        };
    }

    /// A key change must fall on a record boundary (§5.1): a message
    /// already received under the old keys that would be read under the
    /// new ones is a violation.
    pub fn installReadKeys(h: *Handshake, secret: Secret) Error!void {
        if (h.inbox_pos != h.inbox.items.len) return error.TlsUnexpectedMessage;
        if (h.conn.read.keys) |*old| old.deinit();
        h.conn.read.keys = cipher.Keys.init(h.suite, secret) catch return error.TlsInternalError;
    }

    pub fn installWriteKeys(h: *Handshake, secret: Secret) Error!void {
        if (h.conn.write.keys) |*old| old.deinit();
        h.conn.write.keys = cipher.Keys.init(h.suite, secret) catch return error.TlsInternalError;
    }

    // Certificate, CertificateVerify, Finished

    /// A Certificate message with `pair`'s chain, or an empty one, each
    /// certificate with no extensions. `context` is the request context
    /// being answered (empty for a server).
    pub fn writeCertificate(h: *Handshake, context: []const u8, pair: ?*const config.CertKeyPair) Error!void {
        const chain: []const []const u8 = if (pair) |p| p.chain else &.{};
        var list_len: usize = 0;
        for (chain) |der| list_len += 3 + der.len + 2;
        if (list_len > std.math.maxInt(u24) or context.len > std.math.maxInt(u8)) return error.TlsInternalError;
        const body_len = 1 + context.len + 3 + list_len;

        var w = try h.messageWriter();
        try w.write(&.{@intFromEnum(proto.HandshakeType.certificate)});
        try w.int(u24, body_len);
        try w.int(u8, context.len);
        try w.write(context);
        try w.int(u24, list_len);
        for (chain) |der| {
            try w.int(u24, der.len);
            try w.write(der);
            try w.int(u16, 0);
        }
        try w.finish();
    }

    /// The bytes a CertificateVerify signs (§4.4.3): 64 spaces, the
    /// context string, a zero and the transcript hash.
    fn certificateVerifyContent(h: *const Handshake, signer: proto.Side, out: *[64 + 33 + 1 + crypto.hash.max_digest_length]u8) []const u8 {
        const context = switch (signer) {
            .server => "TLS 1.3, server CertificateVerify",
            .client => "TLS 1.3, client CertificateVerify",
        };
        @memset(out[0..64], 0x20);
        @memcpy(out[64..][0..context.len], context);
        out[64 + context.len] = 0;
        const hash = h.transcriptHash(out[64 + context.len + 1 ..][0..crypto.hash.max_digest_length]);
        return out[0 .. 64 + context.len + 1 + hash.len];
    }

    /// Signs the transcript so far with `pair`'s key under `scheme`.
    pub fn writeCertificateVerify(h: *Handshake, pair: *const config.CertKeyPair, scheme: proto.SignatureScheme, signer: proto.Side) Error!void {
        var content_buf: [64 + 33 + 1 + crypto.hash.max_digest_length]u8 = undefined;
        const content = h.certificateVerifyContent(signer, &content_buf);
        var signature_buf: [1024]u8 = undefined;
        if (pair.key.maxSignatureLength() > signature_buf.len) return error.TlsInternalError;
        const signature = pair.key.sign(schemeAlgorithm(scheme).?, content, &signature_buf) catch return error.TlsInternalError;

        var message_buf: [4 + 2 + 2 + signature_buf.len]u8 = undefined;
        var w = codec.Writer.init(&message_buf);
        w.enumValue(proto.HandshakeType.certificate_verify) catch unreachable;
        const len = w.beginLength(u24) catch unreachable;
        w.enumValue(scheme) catch unreachable;
        w.vector(u16, signature) catch unreachable;
        len.end(&w) catch unreachable;
        try h.writeMessage(w.written());
    }

    /// A Finished message for the side whose handshake traffic secret
    /// this is (§4.4.4).
    pub fn writeFinished(h: *Handshake, traffic_secret: *const Secret) Error!void {
        var hash_buf: [crypto.hash.max_digest_length]u8 = undefined;
        const hash = h.transcriptHash(&hash_buf);
        var verify_buf: [crypto.hash.max_digest_length]u8 = undefined;
        const verify_data = key_schedule.verifyData(cipher.suiteHash(h.suite).?, traffic_secret, hash, &verify_buf);

        var message_buf: [4 + crypto.hash.max_digest_length]u8 = undefined;
        var w = codec.Writer.init(&message_buf);
        w.enumValue(proto.HandshakeType.finished) catch unreachable;
        w.int(u24, verify_data.len) catch unreachable;
        w.slice(verify_data) catch unreachable;
        try h.writeMessage(w.written());
    }

    /// Parses a Certificate message. Null for an empty chain, which a
    /// client may send when it has none.
    pub fn parseCertificate(h: *Handshake, body: []const u8, expected_context: []const u8) Error!?PeerCertificate {
        _ = h;
        var d = codec.Decoder.init(body);
        const context = try d.vectorBytes(u8);
        if (!std.mem.eql(u8, context, expected_context)) return error.TlsIllegalParameter;
        var list = try d.vector(u24);
        try d.expectEof();
        if (list.eof()) return null;

        var peer: PeerCertificate = .{ .public_key = undefined };
        errdefer for (peer.chain[0..peer.len]) |*cert| cert.deinit();
        while (!list.eof()) {
            if (peer.len == peer.chain.len) return error.TlsBadCertificate;
            const der = try list.vectorBytes(u24);
            _ = try list.vector(u16); // extensions: status_request, SCTs; not used
            peer.chain[peer.len] = x509.Certificate.parseDer(der) catch return error.TlsBadCertificate;
            peer.len += 1;
        }
        peer.public_key = peer.chain[0].publicKey() catch |err| switch (err) {
            error.UnsupportedKey => return error.TlsUnsupportedCertificate,
            error.CryptoFailed => return error.TlsInternalError,
        };
        return peer;
    }

    /// Verifies the peer's chain against `store`, for its role. `host` is
    /// the name or IP literal a server must be certified for.
    pub fn verifyChain(h: *Handshake, peer: *const PeerCertificate, store: *const x509.TrustStore, purpose: x509.Purpose, host: ?[]const u8, now: i64) Error!void {
        _ = h;
        var options: x509.VerifyOptions = .{ .now = now, .purpose = purpose };
        if (host) |name| {
            if (std.Io.net.IpAddress.parse(name, 0)) |address| {
                options.ip = switch (address) {
                    .ip4 => |a| &a.bytes,
                    .ip6 => |a| &a.bytes,
                };
            } else |_| {
                options.host = name;
            }
        }
        x509.verify(store, peer.chain[0..peer.len], options) catch |err| return switch (err) {
            error.CertificateExpired, error.CertificateNotYetValid => error.TlsCertificateExpired,
            error.UnknownCa => error.TlsUnknownCa,
            error.HostnameMismatch, error.BadCertificate => error.TlsBadCertificate,
            error.CryptoFailed => error.TlsInternalError,
        };
    }

    /// Checks a CertificateVerify against the transcript so far and the
    /// peer's key. The scheme must be one we offered and suit the key.
    pub fn verifyCertificateVerify(h: *Handshake, body: []const u8, public_key: *const sig.PublicKey, signer: proto.Side) Error!void {
        var d = codec.Decoder.init(body);
        const scheme = try d.decode(proto.SignatureScheme);
        const signature = try d.vectorBytes(u16);
        try d.expectEof();
        if (std.mem.indexOfScalar(proto.SignatureScheme, &signature_algorithms, scheme) == null) return error.TlsIllegalParameter;
        const algorithm = schemeAlgorithm(scheme) orelse return error.TlsIllegalParameter;
        if (!algorithm.suits(public_key.key_type)) return error.TlsIllegalParameter;

        var content_buf: [64 + 33 + 1 + crypto.hash.max_digest_length]u8 = undefined;
        const content = h.certificateVerifyContent(signer, &content_buf);
        public_key.verify(algorithm, content, signature) catch |err| return switch (err) {
            error.SignatureInvalid => error.TlsDecryptError,
            error.AlgorithmMismatch => error.TlsIllegalParameter,
            error.CryptoFailed => error.TlsInternalError,
        };
    }

    /// Checks a Finished against the transcript so far.
    pub fn verifyFinished(h: *Handshake, body: []const u8, traffic_secret: *const Secret) Error!void {
        var hash_buf: [crypto.hash.max_digest_length]u8 = undefined;
        const hash = h.transcriptHash(&hash_buf);
        var verify_buf: [crypto.hash.max_digest_length]u8 = undefined;
        const expected = key_schedule.verifyData(cipher.suiteHash(h.suite).?, traffic_secret, hash, &verify_buf);
        if (body.len != expected.len) return error.TlsDecodeError;
        if (!std.crypto.timing_safe.eql([crypto.hash.max_digest_length]u8, padded(expected), padded(body))) return error.TlsDecryptError;
    }

    fn padded(bytes: []const u8) [crypto.hash.max_digest_length]u8 {
        var out: [crypto.hash.max_digest_length]u8 = @splat(0);
        @memcpy(out[0..bytes.len], bytes);
        return out;
    }
};

const testing = std.testing;
const testu = @import("testu.zig");
const Io = std.Io;

test "key shares agree for every group" {
    for ([_]proto.NamedGroup{ .x25519, .secp256r1, .secp384r1, .x25519_ml_kem768 }) |group| {
        var client = try KeyShares.generate(&.{group});
        defer client.deinit();
        var share_buf: [KeyShares.max_share_len]u8 = undefined;
        const client_share = client.publicShare(group, &share_buf);

        var server_share_buf: [KeyShares.max_share_len]u8 = undefined;
        var server_secret_buf: [KeyShares.max_secret_len]u8 = undefined;
        const response = try KeyShares.respond(group, client_share, &server_share_buf, &server_secret_buf);

        var client_secret_buf: [KeyShares.max_secret_len]u8 = undefined;
        const client_secret = try client.sharedSecret(group, response.share, &client_secret_buf);
        try testing.expectEqualSlices(u8, response.secret, client_secret);

        try testing.expectError(error.TlsIllegalParameter, client.sharedSecret(group, response.share[1..], &client_secret_buf));
        try testing.expectError(error.TlsIllegalParameter, KeyShares.respond(group, client_share[1..], &server_share_buf, &server_secret_buf));
    }
    try testing.expectError(error.TlsInternalError, KeyShares.generate(&.{.ffdhe2048}));
}

test "scheme selection" {
    try testing.expectEqual(proto.SignatureScheme.ecdsa_secp256r1_sha256, selectScheme(.{ .ecdsa = .p256 }, &.{ .rsa_pss_rsae_sha256, .ecdsa_secp256r1_sha256 }).?);
    try testing.expectEqual(null, selectScheme(.{ .ecdsa = .p256 }, &.{ .rsa_pss_rsae_sha256, .ecdsa_secp384r1_sha384 }));
    try testing.expectEqual(proto.SignatureScheme.rsa_pss_rsae_sha384, selectScheme(.{ .rsa = 2048 }, &.{ .rsa_pkcs1_sha256, .rsa_pss_rsae_sha384 }).?);
    try testing.expectEqual(null, selectScheme(.{ .rsa = 2048 }, &.{.rsa_pkcs1_sha256})); // pkcs1 may not sign a CertificateVerify
    try testing.expectEqual(proto.SignatureScheme.ed25519, selectScheme(.ed25519, &.{.ed25519}).?);
}

test "certificate, certificate verify and finished round-trip through records" {
    var pair = try config.CertKeyPair.fromSlice(testing.allocator, @embedFile("testdata/pki/server-chain.pem"), @embedFile("testdata/pki/server-chain.key"));
    defer pair.deinit();

    // The sender writes into a buffer large enough for everything.
    var wire: [64 * 1024]u8 = undefined;
    var output: Io.Writer = .fixed(&wire);
    var unused_input: [@import("connection.zig").input_buffer_len]u8 = undefined;
    var input: Io.Reader = .fixed(&unused_input);
    var sender_conn = Connection.init(&input, &output);
    var sender = Handshake.init(&sender_conn, testing.allocator, 64 * 1024);
    defer sender.deinit();
    sender.setSuite(.aes_128_gcm_sha256);
    sender.transcript.update("ClientHello..ServerHello");
    const secrets = sender.deriveHandshakeSecrets("shared secret");
    try sender.installWriteKeys(secrets.server);

    try sender.writeCertificate("", &pair);
    try sender.writeCertificateVerify(&pair, .ecdsa_secp384r1_sha384, .server);
    try sender.writeFinished(&secrets.server);
    try sender.flush();
    var sent_hash: [crypto.hash.max_digest_length]u8 = undefined;
    const sent = output.buffered();

    // The receiver reads them back through a small transport buffer, so
    // records arrive one at a time and messages span them.
    var input_buffer: [@import("connection.zig").input_buffer_len]u8 = undefined;
    var fixed: Io.Reader = .fixed(sent);
    var limited = fixed.limited(.unlimited, &input_buffer);
    var unused_output: [@import("connection.zig").output_buffer_len]u8 = undefined;
    var discard: Io.Writer = .fixed(&unused_output);
    var receiver_conn = Connection.init(&limited.interface, &discard);
    var receiver = Handshake.init(&receiver_conn, testing.allocator, 64 * 1024);
    defer receiver.deinit();
    receiver.setSuite(.aes_128_gcm_sha256);
    receiver.transcript.update("ClientHello..ServerHello");
    const peer_secrets = receiver.deriveHandshakeSecrets("shared secret");
    try receiver.installReadKeys(peer_secrets.server);

    var msg = try receiver.nextMessage();
    try receiver.expect(msg, .certificate);
    var peer = (try receiver.parseCertificate(msg.body, "")).?;
    defer peer.deinit();
    try testing.expectEqual(2, peer.len);
    try testing.expectEqual(sig.KeyType{ .ecdsa = .p384 }, peer.public_key.key_type);
    var store = try x509.TrustStore.init();
    defer store.deinit();
    _ = try store.addPem(testing.allocator, @embedFile("testdata/pki/ca.pem"));
    try receiver.verifyChain(&peer, &store, .server, "localhost", 1_800_000_000);
    try receiver.verifyChain(&peer, &store, .server, "127.0.0.1", 1_800_000_000);
    try testing.expectError(error.TlsBadCertificate, receiver.verifyChain(&peer, &store, .server, "example.org", 1_800_000_000));
    try testing.expectError(error.TlsCertificateExpired, receiver.verifyChain(&peer, &store, .server, "localhost", 1_000_000_000));
    receiver.hashMessage(msg);

    msg = try receiver.nextMessage();
    try receiver.expect(msg, .certificate_verify);
    try receiver.verifyCertificateVerify(msg.body, &peer.public_key, .server);
    try testing.expectError(error.TlsDecryptError, receiver.verifyCertificateVerify(msg.body, &peer.public_key, .client));
    receiver.hashMessage(msg);

    msg = try receiver.nextMessage();
    try receiver.expect(msg, .finished);
    try receiver.verifyFinished(msg.body, &peer_secrets.server);
    try testing.expectError(error.TlsDecryptError, receiver.verifyFinished(msg.body, &peer_secrets.client));
    receiver.hashMessage(msg);

    // Both transcripts agree, and the sender's hashed exactly what it sent.
    var received_hash: [crypto.hash.max_digest_length]u8 = undefined;
    try testing.expectEqualSlices(u8, sender.transcriptHash(&sent_hash), receiver.transcriptHash(&received_hash));
    try testing.expectError(error.EndOfStream, receiver.nextMessage());
}

test "a handshake message that spans a key change is refused" {
    // ServerHello and EncryptedExtensions in one plaintext record: the
    // second must not be read under the handshake keys.
    var record: [64]u8 = undefined;
    var w = codec.Writer.init(&record);
    try w.enumValue(proto.ContentType.handshake);
    try w.enumValue(proto.Version.tls_1_2);
    const len = try w.beginLength(u16);
    try w.enumValue(proto.HandshakeType.server_hello);
    try w.vector(u24, "x"); // the contents do not matter here
    try w.enumValue(proto.HandshakeType.encrypted_extensions);
    try w.vector(u24, &.{ 0, 0 });
    try len.end(&w);

    var input: Io.Reader = .fixed(w.written());
    var input_buffer: [@import("connection.zig").input_buffer_len]u8 = undefined;
    var limited = input.limited(.unlimited, &input_buffer);
    var output_buffer: [@import("connection.zig").output_buffer_len]u8 = undefined;
    var output: Io.Writer = .fixed(&output_buffer);
    var conn = Connection.init(&limited.interface, &output);
    var h = Handshake.init(&conn, testing.allocator, 1024);
    defer h.deinit();
    h.setSuite(.aes_128_gcm_sha256);

    const msg = try h.nextMessage();
    try h.expect(msg, .server_hello);
    const secrets = h.deriveHandshakeSecrets("shared");
    try testing.expectError(error.TlsUnexpectedMessage, h.installReadKeys(secrets.server));
}

test "an empty certificate and the request context" {
    var wire: [@import("connection.zig").output_buffer_len]u8 = undefined;
    var output: Io.Writer = .fixed(&wire);
    var unused_input: [@import("connection.zig").input_buffer_len]u8 = undefined;
    var input: Io.Reader = .fixed(&unused_input);
    var conn = Connection.init(&input, &output);
    var h = Handshake.init(&conn, testing.allocator, 1024);
    defer h.deinit();
    h.setSuite(.aes_128_gcm_sha256);
    try h.writeCertificate("ctx", null);
    try testing.expectEqualSlices(u8, &.{ 22, 3, 3, 0, 11, 11, 0, 0, 7, 3, 'c', 't', 'x', 0, 0, 0 }, output.buffered());
    try testing.expectEqual(null, try h.parseCertificate(output.buffered()[9..], "ctx"));
    try testing.expectError(error.TlsIllegalParameter, h.parseCertificate(output.buffered()[9..], ""));
}
