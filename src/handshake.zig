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
const connection = @import("connection.zig");
const Connection = connection.Connection;

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

/// The ServerHello.random that makes it a HelloRetryRequest (§4.2.3).
pub const hello_retry_request_random = [32]u8{
    0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11, 0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
    0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E, 0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C,
};

/// The algorithm a scheme stands for when it signs a handshake in
/// `version`: a CertificateVerify, or in TLS 1.2 a ServerKeyExchange too.
/// Null for one that may not: the rsa_pkcs1 ones in TLS 1.3 (§4.2.3), and
/// any scheme we do not implement.
pub fn schemeAlgorithm(scheme: proto.SignatureScheme, version: cipher.Version) ?sig.Algorithm {
    return switch (scheme) {
        .ecdsa_secp256r1_sha256 => .ecdsa_sha256,
        .ecdsa_secp384r1_sha384 => .ecdsa_sha384,
        .ecdsa_secp521r1_sha512 => .ecdsa_sha512,
        .ed25519 => .ed25519,
        .rsa_pss_rsae_sha256 => .rsa_pss_sha256,
        .rsa_pss_rsae_sha384 => .rsa_pss_sha384,
        .rsa_pss_rsae_sha512 => .rsa_pss_sha512,
        .rsa_pkcs1_sha256 => if (proto.tls12_enabled and version == .tls12) .rsa_pkcs1_sha256 else null,
        .rsa_pkcs1_sha384 => if (proto.tls12_enabled and version == .tls12) .rsa_pkcs1_sha384 else null,
        .rsa_pkcs1_sha512 => if (proto.tls12_enabled and version == .tls12) .rsa_pkcs1_sha512 else null,
        else => null,
    };
}

/// Whether a key of `key_type` may sign a handshake under `scheme` in
/// `version`: the algorithm must suit the kind of key, and in TLS 1.3 an
/// ECDSA scheme names the key's curve too (§4.2.3). TLS 1.2 schemes name
/// only the hash (RFC 5246 §7.4.1.4.1); there the leaf's curve is checked
/// against supported_groups instead.
pub fn schemeSuits(scheme: proto.SignatureScheme, key_type: sig.KeyType, version: cipher.Version) bool {
    const algorithm = schemeAlgorithm(scheme, version) orelse return false;
    if (!algorithm.suits(key_type)) return false;
    if (version == .tls12) return true;
    const curve: sig.Curve = switch (scheme) {
        .ecdsa_secp256r1_sha256 => .p256,
        .ecdsa_secp384r1_sha384 => .p384,
        .ecdsa_secp521r1_sha512 => .p521,
        else => return true,
    };
    return switch (key_type) {
        .ecdsa => |key_curve| key_curve == curve,
        else => false,
    };
}

/// Whether `schemes` are all ones we implement, none twice.
pub fn schemesSupported(schemes: []const proto.SignatureScheme) bool {
    for (schemes, 0..) |scheme, i| {
        if (std.mem.indexOfScalar(proto.SignatureScheme, &config.default_signature_schemes, scheme) == null) return false;
        if (std.mem.indexOfScalar(proto.SignatureScheme, schemes[0..i], scheme) != null) return false;
    }
    return true;
}

/// The scheme to sign with in `version`: the first of `ours` that the
/// peer offered and that suits the key.
pub fn selectScheme(ours: []const proto.SignatureScheme, key_type: sig.KeyType, offered: []const proto.SignatureScheme, version: cipher.Version) ?proto.SignatureScheme {
    for (ours) |scheme| {
        if (!schemeSuits(scheme, key_type, version)) continue;
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

/// The longest handshake message other than a Certificate or a
/// CertificateRequest.
pub const max_small_message_len = 16 * 1024;

pub const Handshake = struct {
    conn: *Connection,
    allocator: Allocator,
    max_message_len: usize,
    transcript: key_schedule.Transcript,
    schedule: ?key_schedule.KeySchedule = null,
    suite: proto.CipherSuite = undefined,
    /// Received handshake bytes not yet taken as messages: in the last
    /// record, where it was opened in the transport's buffer, or in
    /// `inbox` when a message spans records. The former relies on nothing
    /// reading `input` between handshake records.
    pending: []const u8 = &.{},
    /// A message that spans records, gathered from them, and what follows
    /// it in the record it ends in. Empty otherwise, so that most
    /// handshakes allocate nothing for it.
    inbox: std.ArrayList(u8) = .empty,
    /// A change_cipher_spec may arrive once the first ClientHello has been
    /// sent or received (§5).
    ccs_allowed: bool = false,
    /// Warning alerts other than close_notify are ignored, as TLS 1.2 has
    /// them (RFC 5246 §7.2): set by a client that offers TLS 1.2, until a
    /// TLS 1.3 ServerHello. A server sends one (unrecognized_name, often)
    /// before it knows which version it will speak.
    tolerate_warnings: bool = false,
    /// Warning alerts in a row, capped as on an open connection.
    warning_alerts: u32 = 0,
    /// The handshake messages so far, while `keepRawTranscript` is on.
    raw_transcript: ?std.ArrayList(u8) = null,
    /// legacy_record_version of the plaintext records we write. A client's
    /// first ClientHello says TLS 1.0, as every major stack's does and
    /// RFC 9846 §5.1 allows, for servers that choke on anything newer.
    record_version: proto.Version = .tls_1_2,

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
        h.dropRawTranscript();
        if (h.schedule) |*s| s.deinit();
        h.* = undefined;
    }

    // Receiving

    /// The next handshake message from the peer, whole, reassembled across
    /// records if need be. It is valid until the next record is read, by
    /// the next `nextMessage` or `readChangeCipherSpec`. The caller hashes
    /// it into the transcript (`hashMessage`) once it is dealt with.
    pub fn nextMessage(h: *Handshake) Error!Message {
        while (true) {
            if (h.pending.len >= 4) {
                const len = std.mem.readInt(u24, h.pending[1..4], .big);
                // Bigger than we take; the peer's doing, so it hears so.
                if (len > h.maxMessageLen(h.pending[0])) return error.TlsIllegalParameter;
                if (h.pending.len >= 4 + len) {
                    const raw = h.pending[0 .. 4 + len];
                    h.pending = h.pending[raw.len..];
                    return .{ .handshake_type = @enumFromInt(raw[0]), .body = raw[4..], .raw = raw };
                }
            }
            try h.readHandshakeRecord();
        }
    }

    /// Certificate chains, and the CA names a CertificateRequest may list,
    /// take up to `max_message_len`; nothing else needs more than
    /// `max_small_message_len`.
    fn maxMessageLen(h: *const Handshake, handshake_type: u8) usize {
        return switch (@as(proto.HandshakeType, @enumFromInt(handshake_type))) {
            .certificate, .certificate_request => h.max_message_len,
            else => @min(h.max_message_len, max_small_message_len),
        };
    }

    /// Reads the next handshake record. Its payload is used where it was
    /// opened, unless part of a message is pending: then it joins that in
    /// the inbox. Alerts end the handshake; application data is out of
    /// place.
    fn readHandshakeRecord(h: *Handshake) Error!void {
        // The next read may reuse the transport buffer that pending bytes
        // from the last record are in: they move to the inbox first. With
        // nothing pending, the last message is done with, and the inbox
        // is free for the next one that spans records.
        if (h.pending.len > 0) try h.spill() else h.inbox.clearRetainingCapacity();
        // Not between the fragments of a message: nothing may come between
        // those (§5.1).
        h.conn.read.ccs = if (h.ccs_allowed and h.pending.len == 0) .drop else .refuse;
        const record = try h.readRecord();
        if (record.content_type != .handshake) return error.TlsUnexpectedMessage;
        if (record.payload.len == 0) return error.TlsUnexpectedMessage;
        if (h.pending.len == 0) {
            h.pending = record.payload;
            return;
        }
        // The inbox holds less than one message, which `nextMessage` caps
        // at `max_message_len`, so it stays bounded.
        try h.inbox.appendSlice(h.allocator, record.payload);
        h.pending = h.inbox.items;
    }

    /// Moves the pending bytes, a message not yet whole, to the start of
    /// the inbox, with room for at least the next record's worth of it.
    /// Room for all of it waits until it arrives: the length is only the
    /// peer's word.
    fn spill(h: *Handshake) Error!void {
        const len = h.pending.len;
        // In the inbox, pending is what is left at its end.
        assert(h.inbox.items.len == 0 or h.pending.ptr + len == h.inbox.items.ptr + h.inbox.items.len);
        const total = if (len >= 4) 4 + @as(usize, std.mem.readInt(u24, h.pending[1..4], .big)) else len;
        const want = @min(total, len + cipher.max_plaintext_len);
        if (h.inbox.items.len > 0) {
            // Already in the inbox, at its end, and usually all of it.
            if (h.pending.ptr != h.inbox.items.ptr) std.mem.copyForwards(u8, h.inbox.items[0..len], h.pending);
            h.inbox.shrinkRetainingCapacity(len);
        }
        // Doubling, so a message in small records is not reallocated for
        // every one of them.
        if (h.inbox.capacity < want) try h.inbox.ensureTotalCapacityPrecise(h.allocator, @min(total, @max(want, 2 * h.inbox.capacity)));
        if (h.inbox.items.len == 0) h.inbox.appendSliceAssumeCapacity(h.pending);
        h.pending = h.inbox.items;
    }

    /// The next record that is not an alert to carry on past. Alerts end
    /// the handshake otherwise; application data is out of place.
    fn readRecord(h: *Handshake) Error!Connection.Record {
        while (true) {
            const record = h.conn.readRecord(null) catch |err| switch (err) {
                error.EndOfStream => return error.EndOfStream,
                error.ReadFailed => return error.ReadFailed,
                else => |e| return e,
            };
            if (record.content_type != .alert) {
                h.warning_alerts = 0;
                if (record.content_type == .application_data) return error.TlsUnexpectedMessage;
                return record;
            }
            if (record.payload.len != 2) return error.TlsDecodeError;
            const alert = proto.Alert.decode(record.payload[0..2]);
            if (h.tolerate_warnings and record.payload[0] == @intFromEnum(proto.Alert.Level.warning) and alert != .close_notify) {
                h.warning_alerts += 1;
                if (h.warning_alerts > connection.max_warning_alerts) return error.TlsUnexpectedMessage;
                continue;
            }
            if (alert.toError()) |err| return err;
            // close_notify during the handshake: the peer gave up.
            if (alert == .close_notify) return error.EndOfStream;
            // user_canceled, with close_notify to follow, within the cap
            // on warnings.
            h.warning_alerts += 1;
            if (h.warning_alerts > connection.max_warning_alerts) return error.TlsUnexpectedMessage;
        }
    }

    /// TLS 1.2: the peer's change_cipher_spec, which has to be next, on a
    /// message boundary (RFC 5246 §7.1); the caller then switches the read
    /// keys.
    pub fn readChangeCipherSpec(h: *Handshake) Error!void {
        if (h.pending.len != 0) return error.TlsUnexpectedMessage;
        h.conn.read.ccs = .deliver;
        defer h.conn.read.ccs = .refuse;
        const record = try h.readRecord();
        if (record.content_type != .change_cipher_spec) return error.TlsUnexpectedMessage;
    }

    /// Fails unless the message is of the expected type.
    pub fn expect(h: *Handshake, message: Message, handshake_type: proto.HandshakeType) Error!void {
        _ = h;
        if (message.handshake_type != handshake_type) return error.TlsUnexpectedMessage;
    }

    pub fn hashMessage(h: *Handshake, message: Message) Error!void {
        try h.addTranscript(message.raw);
    }

    /// Hashes `bytes` into the transcript, and keeps them too while
    /// `raw_transcript` is on.
    fn addTranscript(h: *Handshake, bytes: []const u8) Error!void {
        h.transcript.update(bytes);
        if (!proto.tls12_enabled) return;
        if (h.raw_transcript) |*raw| try raw.appendSlice(h.allocator, bytes);
    }

    /// Starts keeping the handshake messages themselves, for a TLS 1.2
    /// CertificateVerify, which signs them rather than their hash
    /// (RFC 5246 §7.4.8) with whatever hash the server lets us use.
    pub fn keepRawTranscript(h: *Handshake) void {
        assert(h.raw_transcript == null);
        h.raw_transcript = .empty;
    }

    pub fn dropRawTranscript(h: *Handshake) void {
        if (h.raw_transcript) |*raw| raw.deinit(h.allocator);
        h.raw_transcript = null;
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
            try w.h.addTranscript(bytes);
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
            assert(w.window.ptr == unused.ptr + payloadOffset(c));
            const record_len = if (c.write.keys) |*keys| blk: {
                keys.seal(unused, .handshake, w.len) catch return error.TlsInternalError;
                break :blk keys.sealedLen(w.len);
            } else blk: {
                unused[0] = @intFromEnum(proto.ContentType.handshake);
                std.mem.writeInt(u16, unused[1..3], @intFromEnum(w.h.record_version), .big);
                std.mem.writeInt(u16, unused[3..5], @intCast(w.len), .big);
                break :blk cipher.header_len + w.len;
            };
            c.output.advance(record_len);
            try flushIfFull(c);
            w.window = recordWindow(c);
            w.len = 0;
        }
    };

    /// Where a record's plaintext starts: after the header, and after the
    /// explicit nonce of TLS 1.2 AES-GCM.
    fn payloadOffset(c: *const Connection) usize {
        return if (c.write.keys) |*keys| keys.payloadOffset() else cipher.header_len;
    }

    /// Where the next record's plaintext goes in `output`.
    fn recordWindow(c: *Connection) []u8 {
        const unused = c.output.unusedCapacitySlice();
        const offset = payloadOffset(c);
        const overhead: usize = if (c.write.keys) |*keys| offset + keys.trailerLen() else offset;
        assert(unused.len > overhead);
        return unused[offset..][0..@min(cipher.max_plaintext_len, unused.len - overhead)];
    }

    pub fn messageWriter(h: *Handshake) Error!MessageWriter {
        try flushIfFull(h.conn);
        return .{ .h = h, .window = recordWindow(h.conn) };
    }

    /// Handshake records fill what is left of `output`, so that a flight
    /// goes out in one transport write; only a sliver is not worth a
    /// record of its own.
    const min_record_room = 512;

    fn flushIfFull(c: *Connection) Error!void {
        if (c.output.unusedCapacityLen() < min_record_room) {
            c.output.flush() catch return error.WriteFailed;
        }
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

    /// Fixes the suite, and with it the version: the transcript hash
    /// follows it, and in TLS 1.3 the key schedule.
    pub fn setSuite(h: *Handshake, suite: proto.CipherSuite) void {
        assert(h.schedule == null);
        const hash_algorithm = cipher.suiteHash(suite).?;
        h.suite = suite;
        h.conn.suite = suite;
        h.conn.version = suite.version().?;
        h.transcript.select(hash_algorithm);
        if (suite.version() == .tls_1_3) h.schedule = key_schedule.KeySchedule.init(hash_algorithm);
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

    /// A flight has been read in full: handshake data beyond it in the
    /// same record is the peer getting ahead of what it can know, and is
    /// refused (as with a key change).
    pub fn expectFlightEnd(h: *Handshake) Error!void {
        if (h.pending.len != 0) return error.TlsUnexpectedMessage;
    }

    /// A key change must fall on a record boundary (§5.1): a message
    /// already received under the old keys that would be read under the
    /// new ones is a violation.
    pub fn installReadKeys(h: *Handshake, secret: Secret) Error!void {
        if (h.pending.len != 0) return error.TlsUnexpectedMessage;
        var keys = cipher.Keys.init(h.suite, secret) catch return error.TlsInternalError;
        cipher.Keys.replace(&h.conn.read.keys, &keys);
    }

    pub fn installWriteKeys(h: *Handshake, secret: Secret) Error!void {
        var keys = cipher.Keys.init(h.suite, secret) catch return error.TlsInternalError;
        cipher.Keys.replace(&h.conn.write.keys, &keys);
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

    /// The bytes a CertificateVerify signs (§4.5.2): 64 spaces, the
    /// context string, a zero and the transcript hash.
    fn certificateVerifyContent(h: *const Handshake, side: proto.Side, out: *[64 + 33 + 1 + crypto.hash.max_digest_length]u8) []const u8 {
        const context = switch (side) {
            .server => "TLS 1.3, server CertificateVerify",
            .client => "TLS 1.3, client CertificateVerify",
        };
        @memset(out[0..64], 0x20);
        @memcpy(out[64..][0..context.len], context);
        out[64 + context.len] = 0;
        const hash = h.transcriptHash(out[64 + context.len + 1 ..][0..crypto.hash.max_digest_length]);
        return out[0 .. 64 + context.len + 1 + hash.len];
    }

    /// Signs the transcript so far with `pair`'s key under `scheme`,
    /// through the pair's signer when it has one.
    pub fn writeCertificateVerify(h: *Handshake, pair: *const config.CertKeyPair, scheme: proto.SignatureScheme, side: proto.Side) Error!void {
        var content_buf: [64 + 33 + 1 + crypto.hash.max_digest_length]u8 = undefined;
        const content = h.certificateVerifyContent(side, &content_buf);
        try h.writeSignedCertificateVerify(pair, scheme, schemeAlgorithm(scheme, .tls13).?, content);
    }

    /// TLS 1.2's CertificateVerify (RFC 5246 §7.4.8): the handshake
    /// messages so far, signed whole, which `keepRawTranscript` kept.
    pub fn writeCertificateVerifyTls12(h: *Handshake, pair: *const config.CertKeyPair, scheme: proto.SignatureScheme) Error!void {
        const content = h.raw_transcript.?.items;
        try h.writeSignedCertificateVerify(pair, scheme, schemeAlgorithm(scheme, .tls12).?, content);
    }

    fn writeSignedCertificateVerify(h: *Handshake, pair: *const config.CertKeyPair, scheme: proto.SignatureScheme, algorithm: sig.Algorithm, content: []const u8) Error!void {
        var signature_buf: [1024]u8 = undefined;
        if (pair.key.maxSignatureLength() > signature_buf.len) return error.TlsInternalError;
        const signature = if (pair.signer) |s| blk: {
            const signed = s.sign(s.context, &pair.key, algorithm, content, &signature_buf) catch return error.TlsInternalError;
            // The hook's result has to be a slice of the buffer it was
            // given; anything else is its bug, not the peer's.
            const start = @intFromPtr(signed.ptr) -% @intFromPtr(&signature_buf);
            if (start > signature_buf.len or signed.len > signature_buf.len - start) return error.TlsInternalError;
            break :blk signed;
        } else pair.key.sign(algorithm, content, &signature_buf) catch return error.TlsInternalError;

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
    /// this is (§4.5.3).
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
    /// client may send when it has none. The chain's DER is kept on the
    /// connection for the application.
    pub fn parseCertificate(h: *Handshake, body: []const u8, expected_context: []const u8) Error!?PeerCertificate {
        var d = codec.Decoder.init(body);
        const context = try d.vectorBytes(u8);
        if (!std.mem.eql(u8, context, expected_context)) return error.TlsIllegalParameter;
        var list = try d.vector(u24);
        try d.expectEof();
        if (list.eof()) return null;
        var peer = try h.parseChain(&list, .tls13);
        errdefer peer.deinit();
        if (!peer.chain[0].allowsDigitalSignature()) return error.TlsBadCertificate;
        return peer;
    }

    /// Parses a TLS 1.2 Certificate message (RFC 5246 §7.4.2): the bare
    /// list, with no context and no extensions. Null for an empty one.
    /// The leaf's key usage is the caller's to check, against the suite.
    pub fn parseCertificateTls12(h: *Handshake, body: []const u8) Error!?PeerCertificate {
        var d = codec.Decoder.init(body);
        var list = try d.vector(u24);
        try d.expectEof();
        if (list.eof()) return null;
        return try h.parseChain(&list, .tls12);
    }

    /// The certificates of a non-empty certificate_list, and the leaf's key.
    fn parseChain(h: *Handshake, list: *codec.Decoder, version: cipher.Version) Error!PeerCertificate {
        var peer: PeerCertificate = .{ .public_key = undefined };
        errdefer for (peer.chain[0..peer.len]) |*cert| cert.deinit();
        var copies: std.ArrayList([]const u8) = .empty;
        errdefer {
            for (copies.items) |der| h.allocator.free(der);
            copies.deinit(h.allocator);
        }
        while (!list.eof()) {
            if (peer.len == peer.chain.len) return error.TlsBadCertificate;
            const der = try list.vectorBytes(u24);
            if (der.len == 0) return error.TlsDecodeError;
            if (version == .tls13) {
                // Extensions here answer a request (status_request, SCTs)
                // we never make (§4.5.1), so none may come.
                const extensions = try list.vector(u16);
                if (!extensions.eof()) return error.TlsUnsupportedExtension;
            }
            peer.chain[peer.len] = x509.Certificate.parseDer(der) catch return error.TlsDecodeError;
            peer.len += 1;
            try copies.ensureUnusedCapacity(h.allocator, 1);
            copies.appendAssumeCapacity(try h.allocator.dupe(u8, der));
        }
        peer.public_key = peer.chain[0].publicKey() catch |err| switch (err) {
            error.UnsupportedKey => return error.TlsUnsupportedCertificate,
            error.CryptoFailed => return error.TlsInternalError,
        };
        errdefer peer.public_key.deinit();
        h.conn.peer_certificates = try copies.toOwnedSlice(h.allocator);
        h.conn.allocator = h.allocator;
        return peer;
    }

    /// Verifies the peer's chain against `store`, for its role. `host` is
    /// the name or IP literal a server must be certified for.
    pub fn verifyChain(h: *Handshake, peer: *const PeerCertificate, store: *const x509.TrustStore, purpose: x509.Purpose, host: ?[]const u8, now: i64) Error!void {
        _ = h;
        var options: x509.VerifyOptions = .{ .now = now, .purpose = purpose };
        // `options.ip` points into this.
        var address: std.Io.net.IpAddress = undefined;
        if (host) |name| {
            if (std.Io.net.IpAddress.parse(name, 0)) |parsed| {
                address = parsed;
                options.ip = switch (address) {
                    .ip4 => |*a| &a.bytes,
                    .ip6 => |*a| &a.bytes,
                };
            } else |_| {
                options.host = name;
            }
        }
        x509.verify(store, peer.chain[0..peer.len], options) catch |err| return switch (err) {
            error.CertificateExpired => error.CertificateExpired,
            error.CertificateNotYetValid => error.CertificateNotYetValid,
            error.UnknownCa => error.CertificateIssuerNotFound,
            error.HostnameMismatch => error.CertificateHostMismatch,
            error.BadCertificate => error.TlsBadCertificate,
            error.CryptoFailed => error.TlsInternalError,
        };
    }

    /// Checks a CertificateVerify against the transcript so far and the
    /// peer's key. The scheme must be one of `accepted`, the ones we
    /// offered, and suit the key.
    pub fn verifyCertificateVerify(h: *Handshake, body: []const u8, public_key: *const sig.PublicKey, side: proto.Side, accepted: []const proto.SignatureScheme) Error!void {
        var d = codec.Decoder.init(body);
        const scheme = try d.decode(proto.SignatureScheme);
        const signature = try d.vectorBytes(u16);
        try d.expectEof();
        if (std.mem.indexOfScalar(proto.SignatureScheme, accepted, scheme) == null) return error.TlsIllegalParameter;
        if (!schemeSuits(scheme, public_key.key_type, .tls13)) return error.TlsIllegalParameter;
        const algorithm = schemeAlgorithm(scheme, .tls13).?;
        h.conn.peer_signature_scheme = scheme;

        var content_buf: [64 + 33 + 1 + crypto.hash.max_digest_length]u8 = undefined;
        const content = h.certificateVerifyContent(side, &content_buf);
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
    try testing.expectEqual(proto.SignatureScheme.ecdsa_secp256r1_sha256, selectScheme(&config.default_signature_schemes, .{ .ecdsa = .p256 }, &.{ .rsa_pss_rsae_sha256, .ecdsa_secp256r1_sha256 }, .tls13).?);
    try testing.expectEqual(null, selectScheme(&config.default_signature_schemes, .{ .ecdsa = .p256 }, &.{ .rsa_pss_rsae_sha256, .ecdsa_secp384r1_sha384 }, .tls13));
    try testing.expectEqual(proto.SignatureScheme.rsa_pss_rsae_sha384, selectScheme(&config.default_signature_schemes, .{ .rsa = 2048 }, &.{ .rsa_pkcs1_sha256, .rsa_pss_rsae_sha384 }, .tls13).?);
    try testing.expectEqual(null, selectScheme(&config.default_signature_schemes, .{ .rsa = 2048 }, &.{.rsa_pkcs1_sha256}, .tls13)); // pkcs1 may not sign a CertificateVerify
    try testing.expectEqual(proto.SignatureScheme.ed25519, selectScheme(&config.default_signature_schemes, .ed25519, &.{.ed25519}, .tls13).?);
    // Our order, not the peer's; and only what we list.
    try testing.expectEqual(proto.SignatureScheme.rsa_pss_rsae_sha512, selectScheme(&.{ .rsa_pss_rsae_sha512, .rsa_pss_rsae_sha256 }, .{ .rsa = 2048 }, &.{ .rsa_pss_rsae_sha256, .rsa_pss_rsae_sha512 }, .tls13).?);
    try testing.expectEqual(null, selectScheme(&.{.rsa_pss_rsae_sha384}, .{ .rsa = 2048 }, &.{.rsa_pss_rsae_sha256}, .tls13));
}

test "TLS 1.3 binds each ECDSA scheme to a curve" {
    try testing.expect(schemeSuits(.ecdsa_secp256r1_sha256, .{ .ecdsa = .p256 }, .tls13));
    try testing.expect(!schemeSuits(.ecdsa_secp256r1_sha256, .{ .ecdsa = .p384 }, .tls13));
    try testing.expect(schemeSuits(.ecdsa_secp384r1_sha384, .{ .ecdsa = .p384 }, .tls13));
    try testing.expect(!schemeSuits(.ecdsa_secp384r1_sha384, .{ .ecdsa = .p521 }, .tls13));
    try testing.expect(schemeSuits(.ecdsa_secp521r1_sha512, .{ .ecdsa = .p521 }, .tls13));
    try testing.expect(!schemeSuits(.ecdsa_secp521r1_sha512, .{ .rsa = 2048 }, .tls13));
    try testing.expect(schemeSuits(.rsa_pss_rsae_sha256, .{ .rsa = 4096 }, .tls13));
    try testing.expect(!schemeSuits(.rsa_pkcs1_sha256, .{ .rsa = 2048 }, .tls13));
    try testing.expect(!schemeSuits(.ed25519, .{ .ecdsa = .p256 }, .tls13));
}

test "TLS 1.2 schemes name the hash only, and take PKCS#1 v1.5" {
    if (!proto.tls12_enabled) return error.SkipZigTest;
    try testing.expect(schemeSuits(.ecdsa_secp256r1_sha256, .{ .ecdsa = .p384 }, .tls12));
    try testing.expect(schemeSuits(.ecdsa_secp521r1_sha512, .{ .ecdsa = .p256 }, .tls12));
    try testing.expect(!schemeSuits(.ecdsa_secp256r1_sha256, .{ .rsa = 2048 }, .tls12));
    try testing.expect(schemeSuits(.rsa_pkcs1_sha256, .{ .rsa = 2048 }, .tls12));
    try testing.expect(schemeSuits(.rsa_pss_rsae_sha512, .{ .rsa = 2048 }, .tls12));
    try testing.expect(!schemeSuits(.rsa_pkcs1_sha384, .{ .ecdsa = .p384 }, .tls12));
    try testing.expect(schemeSuits(.ed25519, .ed25519, .tls12));
    try testing.expect(!schemeSuits(.rsa_pkcs1_sha1, .{ .rsa = 2048 }, .tls12));
    try testing.expectEqual(proto.SignatureScheme.rsa_pkcs1_sha256, selectScheme(&config.default_signature_schemes, .{ .rsa = 2048 }, &.{.rsa_pkcs1_sha256}, .tls12).?);
}

test "a CertificateVerify under another curve's scheme is refused" {
    // A P-384 key's genuine ECDSA-SHA256 signature, labelled
    // ecdsa_secp256r1_sha256: valid cryptography, but not in TLS 1.3.
    var key = try sig.PrivateKey.parsePem(testing.allocator, @embedFile("testdata/keys/ec_secp384r1_private_key.pem"));
    defer key.deinit();
    _ = crypto.c.EVP_PKEY_up_ref(key.pkey);
    var public = try sig.PublicKey.fromPkey(key.pkey);
    defer public.deinit();

    var unused_input: [@import("connection.zig").input_buffer_len]u8 = undefined;
    var input: Io.Reader = .fixed(&unused_input);
    var unused_output: [@import("connection.zig").output_buffer_len]u8 = undefined;
    var output: Io.Writer = .fixed(&unused_output);
    var conn = Connection.init(&input, &output, .client);
    defer conn.deinit();
    var h = Handshake.init(&conn, testing.allocator, 1024);
    defer h.deinit();
    h.setSuite(.aes_128_gcm_sha256);

    var content_buf: [64 + 33 + 1 + crypto.hash.max_digest_length]u8 = undefined;
    const content = h.certificateVerifyContent(.server, &content_buf);
    var sig_buf: [256]u8 = undefined;
    const signature = try key.sign(.ecdsa_sha256, content, &sig_buf);
    var body_buf: [4 + sig_buf.len]u8 = undefined;
    var w = codec.Writer.init(&body_buf);
    try w.enumValue(proto.SignatureScheme.ecdsa_secp256r1_sha256);
    try w.vector(u16, signature);
    try testing.expectError(error.TlsIllegalParameter, h.verifyCertificateVerify(w.written(), &public, .server, &config.default_signature_schemes));

    // The same key under its own curve's scheme passes.
    const good = try key.sign(.ecdsa_sha384, content, &sig_buf);
    w = codec.Writer.init(&body_buf);
    try w.enumValue(proto.SignatureScheme.ecdsa_secp384r1_sha384);
    try w.vector(u16, good);
    try h.verifyCertificateVerify(w.written(), &public, .server, &config.default_signature_schemes);
}

test "certificate, certificate verify and finished round-trip through records" {
    var pair = try config.CertKeyPair.fromSlice(testing.allocator, @embedFile("testdata/pki/server-chain.pem"), @embedFile("testdata/pki/server-chain.key"));
    defer pair.deinit(testing.allocator);

    // The sender writes into a buffer large enough for everything.
    var wire: [64 * 1024]u8 = undefined;
    var output: Io.Writer = .fixed(&wire);
    var unused_input: [@import("connection.zig").input_buffer_len]u8 = undefined;
    var input: Io.Reader = .fixed(&unused_input);
    var sender_conn = Connection.init(&input, &output, .client);
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
    var receiver_conn = Connection.init(&limited.interface, &discard, .client);
    defer receiver_conn.deinit();
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
    try store.addPem(testing.allocator, @embedFile("testdata/pki/ca.pem"));
    try receiver.verifyChain(&peer, &store, .server, "localhost", 1_800_000_000);
    try receiver.verifyChain(&peer, &store, .server, "127.0.0.1", 1_800_000_000);
    try testing.expectError(error.CertificateHostMismatch, receiver.verifyChain(&peer, &store, .server, "example.org", 1_800_000_000));
    try testing.expectError(error.CertificateNotYetValid, receiver.verifyChain(&peer, &store, .server, "localhost", 1_000_000_000));
    try receiver.hashMessage(msg);

    msg = try receiver.nextMessage();
    try receiver.expect(msg, .certificate_verify);
    try receiver.verifyCertificateVerify(msg.body, &peer.public_key, .server, &config.default_signature_schemes);
    try testing.expectError(error.TlsDecryptError, receiver.verifyCertificateVerify(msg.body, &peer.public_key, .client, &config.default_signature_schemes));
    try receiver.hashMessage(msg);

    msg = try receiver.nextMessage();
    try receiver.expect(msg, .finished);
    try receiver.verifyFinished(msg.body, &peer_secrets.server);
    try testing.expectError(error.TlsDecryptError, receiver.verifyFinished(msg.body, &peer_secrets.client));
    try receiver.hashMessage(msg);

    // Both transcripts agree, and the sender's hashed exactly what it sent.
    var received_hash: [crypto.hash.max_digest_length]u8 = undefined;
    try testing.expectEqualSlices(u8, sender.transcriptHash(&sent_hash), receiver.transcriptHash(&received_hash));
    try testing.expectError(error.EndOfStream, receiver.nextMessage());
}

test "a flight goes out in one transport write" {
    var pair = try config.CertKeyPair.fromSlice(testing.allocator, @embedFile("testdata/pki/server-ec.pem"), @embedFile("testdata/pki/server-ec.key"));
    defer pair.deinit(testing.allocator);

    var output_buffer: [@import("connection.zig").output_buffer_len]u8 = undefined;
    var output: Io.Writer.Discarding = .init(&output_buffer);
    var unused_input: [@import("connection.zig").input_buffer_len]u8 = undefined;
    var input: Io.Reader = .fixed(&unused_input);
    var conn = Connection.init(&input, &output.writer, .server);
    defer conn.deinit();
    var h = Handshake.init(&conn, testing.allocator, 64 * 1024);
    defer h.deinit();
    h.setSuite(.aes_128_gcm_sha256);
    h.transcript.update("ClientHello..ServerHello");
    const secrets = h.deriveHandshakeSecrets("shared secret");
    try h.installWriteKeys(secrets.server);

    try h.writeCertificate("", &pair);
    try h.writeCertificateVerify(&pair, .ecdsa_secp256r1_sha256, .server);
    try h.writeFinished(&secrets.server);
    try testing.expectEqual(0, output.count);
    const flight = output.writer.end;
    try h.flush();
    try testing.expectEqual(flight, output.count);
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
    var conn = Connection.init(&limited.interface, &output, .client);
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
    var conn = Connection.init(&input, &output, .client);
    var h = Handshake.init(&conn, testing.allocator, 1024);
    defer h.deinit();
    h.setSuite(.aes_128_gcm_sha256);
    try h.writeCertificate("ctx", null);
    try testing.expectEqualSlices(u8, &.{ 22, 3, 3, 0, 11, 11, 0, 0, 7, 3, 'c', 't', 'x', 0, 0, 0 }, output.buffered());
    try testing.expectEqual(null, try h.parseCertificate(output.buffered()[9..], "ctx"));
    try testing.expectError(error.TlsIllegalParameter, h.parseCertificate(output.buffered()[9..], ""));
}

/// Plaintext handshake records of at most `fragment` bytes each, carrying
/// `messages` back to back.
fn testFragments(buf: []u8, messages: []const u8, fragment: usize) ![]const u8 {
    var w = codec.Writer.init(buf);
    var rest = messages;
    while (rest.len > 0) {
        const n = @min(fragment, rest.len);
        try w.enumValue(proto.ContentType.handshake);
        try w.enumValue(proto.Version.tls_1_2);
        try w.vector(u16, rest[0..n]);
        rest = rest[n..];
    }
    return w.written();
}

test "only certificate messages may be large, and are not reserved before they arrive" {
    for ([_]proto.HandshakeType{ .client_hello, .certificate }) |handshake_type| {
        // A header that says 40000 bytes, and the first 100 of them.
        var message: [4 + 100]u8 = @splat(0);
        message[0] = @intFromEnum(handshake_type);
        std.mem.writeInt(u24, message[1..4], 40000, .big);
        var wire: [128]u8 = undefined;
        var input: Io.Reader = .fixed(try testFragments(&wire, &message, message.len));
        var input_buffer: [@import("connection.zig").input_buffer_len]u8 = undefined;
        var limited = input.limited(.unlimited, &input_buffer);
        var output_buffer: [@import("connection.zig").output_buffer_len]u8 = undefined;
        var output: Io.Writer = .fixed(&output_buffer);
        var conn = Connection.init(&limited.interface, &output, .client);
        var h = Handshake.init(&conn, testing.allocator, 64 * 1024);
        defer h.deinit();
        if (handshake_type == .certificate) {
            try testing.expectError(error.EndOfStream, h.nextMessage());
            try testing.expect(h.inbox.capacity < 40000);
        } else {
            try testing.expectError(error.TlsIllegalParameter, h.nextMessage());
        }
    }
}

test "a large message in small records is reallocated only a few times" {
    var message: [4 + 40000]u8 = undefined;
    for (&message, 0..) |*b, i| b.* = @truncate(i);
    message[0] = @intFromEnum(proto.HandshakeType.certificate);
    std.mem.writeInt(u24, message[1..4], 40000, .big);
    const wire = try testing.allocator.alloc(u8, message.len / 100 * 105 + 105);
    defer testing.allocator.free(wire);
    var input: Io.Reader = .fixed(try testFragments(wire, &message, 100));
    var input_buffer: [@import("connection.zig").input_buffer_len]u8 = undefined;
    var limited = input.limited(.unlimited, &input_buffer);
    var output_buffer: [@import("connection.zig").output_buffer_len]u8 = undefined;
    var output: Io.Writer = .fixed(&output_buffer);
    var conn = Connection.init(&limited.interface, &output, .client);
    var counting: testu.CountingAllocator = .init(testing.allocator);
    var h = Handshake.init(&conn, counting.allocator(), 64 * 1024);
    defer h.deinit();
    const msg = try h.nextMessage();
    try testing.expectEqualSlices(u8, &message, msg.raw);
    try testing.expect(counting.allocs <= 3);
}

test "messages are taken from records whole, split, or several to a record" {
    var messages: [4 + 3 + 4 + 300 + 4 + 0 + 4 + 40]u8 = undefined;
    {
        var w = codec.Writer.init(&messages);
        try w.enumValue(proto.HandshakeType.server_hello);
        try w.vector(u24, "abc");
        try w.enumValue(proto.HandshakeType.certificate);
        try w.vector(u24, &@as([300]u8, @splat(7)));
        try w.enumValue(proto.HandshakeType.server_hello_done);
        try w.vector(u24, "");
        try w.enumValue(proto.HandshakeType.finished);
        try w.vector(u24, &@as([40]u8, @splat(9)));
        assert(w.written().len == messages.len);
    }
    for ([_]usize{ 1, 2, 3, 5, 7, 100, 305, 311, messages.len }) |fragment| {
        var wire: [4096]u8 = undefined;
        var input: Io.Reader = .fixed(try testFragments(&wire, &messages, fragment));
        var input_buffer: [@import("connection.zig").input_buffer_len]u8 = undefined;
        var limited = input.limited(.unlimited, &input_buffer);
        var output_buffer: [@import("connection.zig").output_buffer_len]u8 = undefined;
        var output: Io.Writer = .fixed(&output_buffer);
        var conn = Connection.init(&limited.interface, &output, .client);
        var counting: testu.CountingAllocator = .init(testing.allocator);
        var h = Handshake.init(&conn, counting.allocator(), 1024);
        defer h.deinit();

        var at: usize = 0;
        for ([_]proto.HandshakeType{ .server_hello, .certificate, .server_hello_done, .finished }) |expected| {
            const msg = try h.nextMessage();
            try testing.expectEqual(expected, msg.handshake_type);
            try testing.expectEqualSlices(u8, messages[at..][0..msg.raw.len], msg.raw);
            at += msg.raw.len;
        }
        try testing.expectEqual(messages.len, at);
        try h.expectFlightEnd();
        // Each message whole in a record: nothing copied. Split: an
        // allocation for a message once its length is known, and a few
        // more when even its header comes a byte at a time.
        if (fragment >= 311) try testing.expectEqual(0, counting.allocs);
        if (fragment >= 7) try testing.expect(counting.allocs <= 2);
        try testing.expect(counting.allocs <= 4);
    }
}
