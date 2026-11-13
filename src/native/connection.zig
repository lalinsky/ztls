//! A TLS 1.3 connection after the handshake: records in and out over the
//! transport's `std.Io.Reader` and `std.Io.Writer`, exposed as a cleartext
//! reader and writer of the same kind.
//!
//! The two directions are independent. One task may read while another
//! writes, with nothing shared but a few atomics, and the read side never
//! writes to the transport: an alert for a failure it found, or the
//! KeyUpdate a peer asked for, is sent by the write side before its next
//! record.

const std = @import("std");
const assert = std.debug.assert;
const Io = std.Io;
const proto = @import("../protocol.zig");
const api = @import("../api.zig");
const cipher = @import("cipher.zig");
const crypto = @import("../crypto.zig");
const codec = @import("codec.zig");

const log = std.log.scoped(.ztls);

pub const input_buffer_len = api.input_buffer_len;
pub const output_buffer_len = api.output_buffer_len;

// The public sizes, worked out from the record layer's own.
comptime {
    assert(input_buffer_len == cipher.max_record_len);
    assert(output_buffer_len == @max(
        cipher.Keys.sealedLenTls13(cipher.max_plaintext_len) + key_update_record_len,
        cipher.max_sealed_record_len,
    ));
}

const key_update_msg_len = 4 + 1;
const key_update_record_len = cipher.Keys.sealedLenTls13(key_update_msg_len);
/// Sealing the first `head` bytes of a window writes past them. In TLS 1.3
/// the content type and tag land at window[head..head + 17], and when a
/// KeyUpdate is moved in ahead the plaintext shifts up by 27 first, so the
/// record ends at window[head + 44]; that much of what follows is saved
/// aside by `rebaseInPlace`. A TLS 1.2 record writes only its 16-byte tag
/// past `head` (the explicit nonce goes before the window), well within.
const seal_spill = cipher.seal_overhead + key_update_record_len;
/// Records carrying no application data (empty ones, post-handshake
/// messages) a peer may send in a row before it is cut off.
const max_idle_records = 32;
/// KeyUpdates a sender may make over a connection's life (§4.7.3).
const max_key_updates: u64 = (1 << 48) - 1;
/// The shortest and longest NewSessionTicket bodies (§4.6.1): lifetime,
/// age_add, a nonce, a ticket and extensions, each at its least and its
/// largest. The ticket has at least one byte.
const min_ticket_len = 4 + 4 + 1 + (2 + 1) + 2;
const max_ticket_len = 4 + 4 + (1 + 255) + (2 + 0xffff) + (2 + 0xffff);

/// Warning alerts a peer may send in a row, with no other record between
/// them, as BoringSSL counts them; TLS 1.3 has only user_canceled. TLS 1.2
/// peers send others (unrecognized_name, say), each ignored.
pub const max_warning_alerts = 4;

pub const Failure = api.Failure;
pub const ReadError = api.ReadError;
pub const WriteError = api.WriteError;
pub const Error = ReadError || WriteError;
/// A direction's state; a failed one's error is in `Shared.read_error` or
/// the writer's `err`.
pub const State = api.State;

pub const Connection = struct {
    /// Ciphertext from the transport. Its buffer holds a whole record.
    input: *Io.Reader,
    /// Ciphertext to the transport. Its buffer holds a whole sealed record.
    output: *Io.Writer,

    read: ReadHalf align(std.atomic.cache_line),
    write: WriteHalf align(std.atomic.cache_line),
    shared: Shared align(std.atomic.cache_line),

    /// The protocol agreed through ALPN, pointing into the configuration.
    alpn_protocol: ?[]const u8 = null,
    /// What the handshake settled on: TLS 1.3 or 1.2, the suite, the
    /// (EC)DHE group.
    version: ?proto.Version = null,
    suite: ?proto.CipherSuite = null,
    group: ?proto.NamedGroup = null,
    /// A HelloRetryRequest was needed.
    retried: bool = false,
    /// The type of key in the peer's certificate, when it sent one.
    peer_key_type: ?crypto.sig.KeyType = null,
    /// The scheme the peer signed its CertificateVerify with.
    peer_signature_scheme: ?proto.SignatureScheme = null,
    /// The peer's certificate chain as it sent it, leaf first, in DER;
    /// copies owned by `gpa`. Empty unless the options'
    /// `keep_peer_certificates` was set and the peer sent one.
    peer_certificates: []const []const u8 = &.{},
    gpa: ?std.mem.Allocator = null,
    server_name_buf: [255]u8 = undefined,
    server_name_len: u8 = 0,
    /// Treat a transport that ends between records without close_notify as
    /// truncated rather than as a clean end.
    strict_close_notify: bool = false,
    /// Which end this is: only a client takes a NewSessionTicket.
    side: proto.Side,
    /// The longest NewSessionTicket taken, as libssl holds it: 16 KiB, or
    /// `max_handshake_message_len` if that is more.
    max_ticket_message_len: u32 = 16 * 1024,

    /// Touched by the reading task only.
    pub const ReadHalf = struct {
        keys: ?cipher.Keys = null,
        /// Cleartext opened in place in `input`'s buffer, not yet handed out.
        cleartext: []u8 = &.{},
        /// Records in a row that carried no application data.
        idle_records: u32 = 0,
        /// change_cipher_spec records seen, and warning alerts in a row,
        /// each capped.
        ccs_records: u32 = 0,
        warning_alerts: u32 = 0,
        /// What a change_cipher_spec does, as the handshake says.
        ccs: CcsMode = .refuse,
        /// Every record must carry legacy_record_version 0x0303, as a TLS
        /// 1.2 handshake demands once the version is agreed. TLS 1.3
        /// ignores the field (RFC 9846 §5.1).
        check_record_version: bool = false,
        /// A post-handshake message split across records.
        message: PartialMessage = .{},
    };

    /// A TLS 1.3 post-handshake message whose records have not all come
    /// (§5.1). Nothing is kept of a NewSessionTicket but how much of it
    /// is still to be skipped, and a KeyUpdate's body is one byte, read
    /// from the record that ends it, so no message needs a buffer.
    pub const PartialMessage = struct {
        /// The header.
        head: [4]u8 = undefined,
        /// How much of `head` has come; 0 between messages.
        len: u8 = 0,
        /// The NewSessionTicket body bytes still to skip.
        skip: u32 = 0,
    };

    pub const CcsMode = enum {
        /// Not now: unexpected_message.
        refuse,
        /// TLS 1.3 middlebox compatibility (§5): one byte of 0x01, dropped.
        drop,
        /// TLS 1.2: handed to the handshake, whose read keys it switches.
        deliver,
    };

    /// Touched by the writing task only.
    pub const WriteHalf = struct {
        keys: ?cipher.Keys = null,
        /// KeyUpdates sent so far, capped at `max_key_updates`.
        key_updates: u64 = 0,
        /// close_notify is sealed in `output`; only a flush is left.
        closing: bool = false,
    };

    /// What the two tasks share. Each state is stored by its own task
    /// only; the other task just loads it.
    pub const Shared = struct {
        read_state: std.atomic.Value(State) = .init(.open),
        write_state: std.atomic.Value(State) = .init(.open),
        /// `@intFromError` of the read side's failure, stored before
        /// `read_state` becomes failed (release), read after seeing it
        /// (acquire).
        read_error: std.atomic.Value(u16) = .init(0),
        /// The alert the read side wants sent, as `@intFromEnum`, or 0.
        pending_alert: std.atomic.Value(u8) = .init(0),
        /// The peer asked for a KeyUpdate; the write side answers.
        key_update_requested: std.atomic.Value(bool) = .init(false),
        /// We asked the peer for a KeyUpdate and none has come since: no
        /// other request may go out until one does (§4.7.3). Set by the
        /// write side before it sends the request, cleared by the read
        /// side on any KeyUpdate from the peer. One that crossed ours
        /// counts, so a second request can go out before the first is
        /// answered; but a peer may fold its answer into a request of its
        /// own (BoringSSL does), which nothing else would clear this for.
        key_update_awaited: std.atomic.Value(bool) = .init(false),
        /// KeyUpdates sent and received, for `keyUpdatesSent` and
        /// `keyUpdatesReceived`, which either task may call.
        key_updates_sent: std.atomic.Value(u64) = .init(0),
        key_updates_received: std.atomic.Value(u64) = .init(0),
    };

    pub fn init(input: *Io.Reader, output: *Io.Writer, side: proto.Side) Connection {
        assert(input.buffer.len >= input_buffer_len);
        assert(output.buffer.len >= output_buffer_len);
        return .{ .input = input, .output = output, .side = side, .read = .{}, .write = .{}, .shared = .{} };
    }

    /// Wipes the keys. Sends nothing; both tasks must be done.
    pub fn deinit(c: *Connection) void {
        if (c.read.keys) |*keys| keys.deinit();
        if (c.write.keys) |*keys| keys.deinit();
        if (c.gpa) |gpa| {
            for (c.peer_certificates) |der| gpa.free(der);
            gpa.free(c.peer_certificates);
        }
        c.* = undefined;
    }

    /// The name in SNI: what a client asked for, as the server saw it, or
    /// what the client sent (none for an IP literal).
    pub fn serverName(c: *const Connection) ?[]const u8 {
        return if (c.server_name_len == 0) null else c.server_name_buf[0..c.server_name_len];
    }

    /// KeyUpdates sent so far, our requests and our answers alike.
    pub fn keyUpdatesSent(c: *const Connection) u64 {
        return c.shared.key_updates_sent.load(.monotonic);
    }

    /// KeyUpdates received so far.
    pub fn keyUpdatesReceived(c: *const Connection) u64 {
        return c.shared.key_updates_received.load(.monotonic);
    }

    pub fn setServerName(c: *Connection, name: ?[]const u8) error{TlsInternalError}!void {
        const n = name orelse "";
        if (n.len > c.server_name_buf.len) return error.TlsInternalError;
        @memcpy(c.server_name_buf[0..n.len], n);
        c.server_name_len = @intCast(n.len);
    }

    // Read side

    /// One record, taken from the transport. The payload points into
    /// `input`'s buffer and lives until the next record is read.
    pub const Record = struct {
        content_type: proto.ContentType,
        payload: []u8,
    };

    pub const ReadRecordError = error{
        ReadFailed,
        /// close_notify, or the transport ended cleanly between records.
        EndOfStream,
        TlsConnectionTruncated,
        TlsRecordOverflow,
        TlsBadRecordMac,
        TlsDecodeError,
        TlsUnexpectedMessage,
        TlsInternalError,
        TlsIllegalParameter,
        TlsProtocolVersion,
    };

    /// The next record. With keys it is opened in place, or into `dest` when
    /// that is given and holds the whole inner plaintext (the payload then
    /// points into `dest`). change_cipher_spec is skipped while the
    /// handshake runs. close_notify and clean transport ends are
    /// `EndOfStream`; other alerts are returned for the caller to act on.
    pub fn readRecord(c: *Connection, dest: ?[]u8) ReadRecordError!Record {
        @setRuntimeSafety(true);
        while (true) {
            const header = c.input.peek(cipher.header_len) catch |err| switch (err) {
                error.EndOfStream => return c.inputEnded(),
                error.ReadFailed => return error.ReadFailed,
            };
            if (proto.tls12_enabled and c.read.check_record_version and std.mem.readInt(u16, header[1..3], .big) != @intFromEnum(proto.Version.tls_1_2)) {
                return error.TlsProtocolVersion;
            }
            const body_len = std.mem.readInt(u16, header[3..5], .big);
            if (body_len > cipher.max_ciphertext_len) return error.TlsRecordOverflow;
            const content_type: proto.ContentType = @enumFromInt(header[0]);
            try c.checkHeader(content_type, body_len);
            const record = c.input.take(cipher.header_len + body_len) catch |err| switch (err) {
                error.EndOfStream => return error.TlsConnectionTruncated,
                error.ReadFailed => return error.ReadFailed,
            };
            const body = record[cipher.header_len..];

            if (c.read.keys) |*keys| {
                // TLS 1.3 hides the content type inside application_data;
                // TLS 1.2 protects each type under its own.
                const protected = switch (keys.version) {
                    .tls13 => content_type == .application_data,
                    .tls12 => content_type == .application_data or content_type == .handshake or content_type == .alert,
                };
                if (protected) {
                    const inner_len = keys.openLen(record.len);
                    // In place: where the ciphertext starts. A record too
                    // short for that fails in `open` before writing.
                    const in_place = record[@min(record.len, keys.payloadOffset())..];
                    const out = if (dest) |d| (if (d.len >= inner_len) d else in_place) else in_place;
                    const opened = keys.open(record, out) catch |err| switch (err) {
                        error.TlsBadRecordMac => return error.TlsBadRecordMac,
                        error.TlsDecodeError => return error.TlsDecodeError,
                        error.TlsRecordOverflow => return error.TlsRecordOverflow,
                        error.TlsUnexpectedMessage => return error.TlsUnexpectedMessage,
                        error.TlsInternalError => return error.TlsInternalError,
                    };
                    return .{ .content_type = opened.content_type, .payload = out[0..opened.len] };
                }
                assert(content_type == .change_cipher_spec);
                if (try c.changeCipherSpec(body)) |r| return r else continue;
            } else {
                switch (content_type) {
                    .handshake, .alert => return .{ .content_type = content_type, .payload = body },
                    .change_cipher_spec => if (try c.changeCipherSpec(body)) |r| return r else continue,
                    else => unreachable,
                }
            }
        }
    }

    /// Refuses what a record's header already rules out, so that no body
    /// is waited for only to be refused, as for an SSLv2-style hello.
    fn checkHeader(c: *Connection, content_type: proto.ContentType, body_len: u16) ReadRecordError!void {
        switch (content_type) {
            .change_cipher_spec => {
                if (c.read.ccs == .refuse) return error.TlsUnexpectedMessage;
                if (body_len != 1) return if (c.read.ccs == .deliver) error.TlsIllegalParameter else error.TlsUnexpectedMessage;
            },
            .application_data => if (c.read.keys == null) return error.TlsUnexpectedMessage,
            .handshake, .alert => if (c.read.keys) |*keys| {
                // TLS 1.3 sends them inside application_data once there
                // are keys.
                if (keys.version == .tls13) return error.TlsUnexpectedMessage;
            } else {
                // Before the handshake keys: ClientHello, ServerHello,
                // HelloRetryRequest and an alert refusing them. Zero-length
                // handshake and alert fragments are forbidden (§5.1), as is
                // a plaintext record over 2^14.
                if (body_len == 0) return error.TlsUnexpectedMessage;
                if (body_len > cipher.max_plaintext_len) return error.TlsRecordOverflow;
            },
            else => return error.TlsUnexpectedMessage,
        }
    }

    /// The transport ran out between records (clean, unless strict) or
    /// inside one (truncated). A clean end is a half-close like
    /// close_notify: the peer may still be reading, so the write direction
    /// goes on until the transport says otherwise.
    fn inputEnded(c: *Connection) ReadRecordError {
        if (c.input.bufferedLen() != 0 or c.strict_close_notify) return error.TlsConnectionTruncated;
        return error.EndOfStream;
    }

    /// Records the read side's failure for both tasks, and the alert the
    /// write side should send for it, if any.
    fn failRead(c: *Connection, err: Failure) void {
        c.shared.read_error.store(@intFromError(err), .monotonic);
        if (proto.Alert.forLocalError(err)) |alert| {
            c.shared.pending_alert.store(@intFromEnum(alert), .monotonic);
        }
        c.shared.read_state.store(.failed, .release);
    }

    const FillError = ReadError || error{EndOfStream};

    /// Fetches cleartext for the application: the next application data
    /// record, into `dest` when it fits there, else opened in place and
    /// kept in `read.cleartext`. Returns how much went into `dest`.
    /// Post-handshake messages and alerts are handled on the way.
    fn fillCleartext(c: *Connection, dest: []u8) FillError!usize {
        assert(c.read.cleartext.len == 0);
        if (c.shared.read_state.load(.monotonic) != .open) {
            return if (c.shared.read_state.load(.acquire) == .closed) error.EndOfStream else error.TlsConnectionFailed;
        }
        while (true) {
            const record = c.readRecord(dest) catch |err| switch (err) {
                error.EndOfStream => {
                    // Even in the middle of a post-handshake message, as
                    // in BoringSSL: what is cut off carries no data and
                    // changes no keys. `strict_close_notify` makes this
                    // truncation, before it gets here.
                    c.shared.read_state.store(.closed, .release);
                    return error.EndOfStream;
                },
                // The transport's failure, often a cancellation or a
                // timeout, and not the connection's: nothing was consumed,
                // so a partial record stays buffered and the read may be
                // retried.
                error.ReadFailed => return error.ReadFailed,
                else => |e| {
                    c.failRead(e);
                    return e;
                },
            };
            // A message split across records has nothing between its
            // pieces but alerts (§5.1), which BoringSSL and s2n let
            // through too.
            if (c.read.message.len != 0 and record.content_type != .handshake and record.content_type != .alert) {
                c.failRead(error.TlsUnexpectedMessage);
                return error.TlsUnexpectedMessage;
            }
            // Empty records leave the count be, as in BoringSSL: they are
            // capped on their own.
            if (record.content_type != .alert and record.payload.len > 0) c.read.warning_alerts = 0;
            switch (record.content_type) {
                .application_data => {
                    if (record.payload.len == 0) {
                        try c.countIdleRecord();
                        continue;
                    }
                    c.read.idle_records = 0;
                    if (record.payload.ptr == dest.ptr) return record.payload.len;
                    c.read.cleartext = record.payload;
                    return 0;
                },
                .alert => {
                    if (record.payload.len != 2) {
                        c.failRead(error.TlsDecodeError);
                        return error.TlsDecodeError;
                    }
                    const level = record.payload[0];
                    if (level != 1 and level != 2) {
                        c.failRead(error.TlsIllegalParameter);
                        return error.TlsIllegalParameter;
                    }
                    const alert = proto.Alert.decode(record.payload[0..2]);
                    // TLS 1.2 warnings other than close_notify are notes,
                    // not failures (RFC 5246 §7.2), within the cap.
                    if (proto.tls12_enabled and level == 1 and alert != .close_notify and c.read.keys.?.version == .tls12) {
                        c.read.warning_alerts += 1;
                        if (c.read.warning_alerts > max_warning_alerts) {
                            c.failRead(error.TlsUnexpectedMessage);
                            return error.TlsUnexpectedMessage;
                        }
                        // Not idle records: warnings and empty records
                        // have caps of their own, as in BoringSSL.
                        continue;
                    }
                    if (alert.toError()) |err| {
                        // The peer's failure, whatever level it claims
                        // (§6): it will not read an alert back.
                        c.failRead(err);
                        return err;
                    }
                    switch (alert) {
                        .close_notify => {
                            // Even in the middle of a post-handshake
                            // message, as at the transport's end.
                            c.shared.read_state.store(.closed, .release);
                            return error.EndOfStream;
                        },
                        // In TLS 1.2 a fatal user_canceled ends the
                        // connection (RFC 5246 §7.2).
                        else => if (proto.tls12_enabled and level == 2 and c.read.keys.?.version == .tls12) {
                            c.failRead(error.TlsAlertUserCanceled);
                            return error.TlsAlertUserCanceled;
                        } else {
                            // user_canceled is followed by close_notify (§6.1).
                            c.read.warning_alerts += 1;
                            if (c.read.warning_alerts > max_warning_alerts) {
                                c.failRead(error.TlsUnexpectedMessage);
                                return error.TlsUnexpectedMessage;
                            }
                            try c.countIdleRecord();
                            continue;
                        },
                    }
                },
                .handshake => {
                    // A peer must not send an empty one (§5.1); like
                    // BoringSSL, we let it, under the idle record cap.
                    if (record.payload.len > 0) c.handlePostHandshake(record.payload) catch |err| {
                        c.failRead(err);
                        return err;
                    };
                    try c.countIdleRecord();
                    continue;
                },
                else => unreachable, // readRecord returns no other type
            }
        }
    }

    /// A change_cipher_spec record, as `read.ccs` says: refused, dropped
    /// (null), or returned to the handshake. Its body is one byte of 0x01.
    fn changeCipherSpec(c: *Connection, body: []u8) ReadRecordError!?Record {
        const valid = body.len == 1 and body[0] == 1;
        switch (c.read.ccs) {
            .refuse => return error.TlsUnexpectedMessage,
            .drop => {
                if (!valid) return error.TlsUnexpectedMessage;
                // One per side is the norm; a flood is a peer wasting our time.
                c.read.ccs_records += 1;
                if (c.read.ccs_records > max_idle_records) return error.TlsUnexpectedMessage;
                return null;
            },
            .deliver => {
                if (!valid) return error.TlsIllegalParameter;
                return .{ .content_type = .change_cipher_spec, .payload = body };
            },
        }
    }

    fn countIdleRecord(c: *Connection) Failure!void {
        c.read.idle_records += 1;
        if (c.read.idle_records > max_idle_records) {
            c.failRead(error.TlsUnexpectedMessage);
            return error.TlsUnexpectedMessage;
        }
    }

    /// Handshake messages after the handshake. In TLS 1.3: KeyUpdate, and
    /// for a client NewSessionTicket, which v1 drops. A message may be
    /// split across records or share one with others (§5.1), but a
    /// KeyUpdate changes the read keys, so it must end its record. In TLS
    /// 1.2 only HelloRequest, the server asking to renegotiate, which we
    /// never do: it is refused with a fatal no_renegotiation (RFC 5746
    /// §4.2), as AWS-LC and Go do by default, so a server waiting for it
    /// fails at once rather than at its timeout.
    fn handlePostHandshake(c: *Connection, payload: []const u8) Failure!void {
        @setRuntimeSafety(true);
        const keys = &c.read.keys.?;
        const tls13 = switch (keys.version) {
            .tls13 => |*tls13| tls13,
            // HelloRequest is refused on its first fragment: a peer may
            // split its four bytes across records, and the rest changes
            // nothing.
            .tls12 => {
                if (!proto.tls12_enabled) unreachable;
                if (payload[0] != @intFromEnum(proto.HandshakeType.hello_request)) return error.TlsUnexpectedMessage;
                for (payload[0..@min(payload.len, 4)]) |b| if (b != 0) return error.TlsDecodeError;
                return error.TlsNoRenegotiation;
            },
        };
        const m = &c.read.message;
        var in = payload;
        while (in.len > 0) {
            if (m.len < 4) {
                const n = @min(4 - m.len, in.len);
                @memcpy(m.head[m.len..][0..n], in[0..n]);
                m.len += @intCast(n);
                in = in[n..];
                if (m.len < 4) return;
                const body_len = std.mem.readInt(u24, m.head[1..4], .big);
                switch (m.head[0]) {
                    @intFromEnum(proto.HandshakeType.key_update) => if (body_len != 1) return error.TlsDecodeError,
                    @intFromEnum(proto.HandshakeType.new_session_ticket) => {
                        if (c.side == .server) return error.TlsUnexpectedMessage;
                        if (body_len > c.max_ticket_message_len) return error.TlsIllegalParameter;
                        if (body_len < min_ticket_len or body_len > max_ticket_len) return error.TlsDecodeError;
                        m.skip = body_len;
                    },
                    else => return error.TlsUnexpectedMessage,
                }
            }
            if (m.head[0] == @intFromEnum(proto.HandshakeType.new_session_ticket)) {
                const n: u32 = @intCast(@min(m.skip, in.len));
                m.skip -= n;
                in = in[n..];
                if (m.skip == 0) m.len = 0;
                continue;
            }
            // A KeyUpdate, waiting for its body.
            if (in.len == 0) return;
            const request: proto.KeyUpdateRequest = @enumFromInt(in[0]);
            m.len = 0;
            if (in.len != 1) return error.TlsUnexpectedMessage;
            in = in[1..];
            switch (request) {
                .update_not_requested => {},
                .update_requested => c.shared.key_update_requested.store(true, .monotonic),
                _ => return error.TlsIllegalParameter,
            }
            c.shared.key_update_awaited.store(false, .monotonic);
            keys.update(tls13) catch return error.TlsInternalError;
            _ = c.shared.key_updates_received.fetchAdd(1, .monotonic);
        }
    }

    pub const Reader = struct {
        conn: *Connection,
        interface: Io.Reader,
        /// Why the last read failed: a `Failure` of the connection, or
        /// `ReadFailed` when the transport reader failed and its own error
        /// says how; that one does not end the connection, and the read
        /// may be retried.
        err: ?ReadError = null,

        fn init(c: *Connection, buffer: []u8) Reader {
            return .{
                .conn = c,
                .interface = .{
                    .vtable = &.{
                        .stream = stream,
                        .readVec = readVec,
                    },
                    .buffer = buffer,
                    .seek = 0,
                    .end = 0,
                },
            };
        }

        fn fail(self: *Reader, err: FillError) Io.Reader.Error {
            switch (err) {
                error.EndOfStream => return error.EndOfStream,
                else => |e| {
                    self.err = e;
                    return error.ReadFailed;
                },
            }
        }

        /// Fills the destinations from the cleartext at hand, then from the
        /// next record, decrypted straight into the first destination when
        /// it fits.
        fn readVec(r: *Io.Reader, data: [][]u8) Io.Reader.Error!usize {
            @setRuntimeSafety(true);
            const self: *Reader = @fieldParentPtr("interface", r);
            const c = self.conn;
            var dest_buffer: [8][]u8 = undefined;
            const dest_n, const data_size = try r.writableVector(&dest_buffer, data);
            const dests = dest_buffer[0..dest_n];

            var n: usize = 0;
            for (dests) |dest| {
                if (dest.len == 0) continue;
                if (c.read.cleartext.len == 0) {
                    // Only block for another record when nothing was
                    // delivered yet.
                    if (n > 0) break;
                    const direct = c.fillCleartext(dest) catch |err| return self.fail(err);
                    if (direct > 0) {
                        n += direct;
                        continue;
                    }
                }
                const len = @min(dest.len, c.read.cleartext.len);
                @memcpy(dest[0..len], c.read.cleartext[0..len]);
                c.read.cleartext = c.read.cleartext[len..];
                n += len;
                if (len < dest.len) break;
            }
            if (n > data_size) {
                r.end += n - data_size;
                return data_size;
            }
            return n;
        }

        fn stream(r: *Io.Reader, w: *Io.Writer, limit: Io.Limit) Io.Reader.StreamError!usize {
            const self: *Reader = @fieldParentPtr("interface", r);
            const c = self.conn;
            const dest = limit.slice(try w.writableSliceGreedy(1));
            if (c.read.cleartext.len == 0) {
                const direct = c.fillCleartext(dest) catch |err| return self.fail(err);
                if (direct > 0) {
                    w.advance(direct);
                    return direct;
                }
            }
            const len = @min(dest.len, c.read.cleartext.len);
            @memcpy(dest[0..len], c.read.cleartext[0..len]);
            c.read.cleartext = c.read.cleartext[len..];
            w.advance(len);
            return len;
        }
    };

    /// The cleartext reader. `buffer` is an ordinary reader buffer that the
    /// application may swap at any time; no connection state lives in it.
    /// One per connection, for the reading task.
    pub fn reader(c: *Connection, buffer: []u8) Reader {
        assert(c.read.keys != null);
        return Reader.init(c, buffer);
    }

    // Write side

    pub const WriteRecordError = error{ WriteFailed, TlsInternalError };

    /// Seals `payload` as one record and puts it in `output`, flushing the
    /// transport first if it does not fit. Nothing else is sent first.
    fn writeRecord(c: *Connection, content_type: proto.ContentType, payload: []const u8) WriteRecordError!void {
        assert(payload.len <= cipher.max_plaintext_len);
        const keys = &c.write.keys.?;
        const record_len = keys.sealedLen(payload.len);
        const dest = c.output.writableSliceGreedy(record_len) catch return error.WriteFailed;
        @memcpy(dest[keys.payloadOffset()..][0..payload.len], payload);
        try keys.seal(dest[0..record_len], content_type, payload.len);
        c.output.advance(record_len);
    }

    /// Before the handshake keys: the record goes out as it is.
    pub fn writePlaintextRecord(c: *Connection, content_type: proto.ContentType, payload: []const u8) error{WriteFailed}!void {
        assert(c.write.keys == null);
        assert(payload.len <= cipher.max_plaintext_len);
        const dest = c.output.writableSliceGreedy(cipher.header_len + payload.len) catch return error.WriteFailed;
        dest[0] = @intFromEnum(content_type);
        std.mem.writeInt(u16, dest[1..3], @intFromEnum(proto.Version.tls_1_2), .big);
        std.mem.writeInt(u16, dest[3..5], @intCast(payload.len), .big);
        @memcpy(dest[cipher.header_len..][0..payload.len], payload);
        c.output.advance(cipher.header_len + payload.len);
    }

    /// An alert, sealed when there are keys. For the handshake; afterwards
    /// alerts go through the write side's own checks.
    pub fn writeAlert(c: *Connection, alert: proto.Alert) WriteRecordError!void {
        if (c.write.keys == null) return c.writePlaintextRecord(.alert, &alert.encode());
        return c.writeRecord(.alert, &alert.encode());
    }

    /// The dummy change_cipher_spec of middlebox compatibility mode (§E.4),
    /// always in the clear.
    pub fn writeChangeCipherSpec(c: *Connection) error{WriteFailed}!void {
        const record = [_]u8{ @intFromEnum(proto.ContentType.change_cipher_spec), 3, 3, 0, 1, 1 };
        const dest = c.output.writableSliceGreedy(record.len) catch return error.WriteFailed;
        dest[0..record.len].* = record;
        c.output.advance(record.len);
    }

    /// Sends what is in `output`.
    fn flushOutput(c: *Connection) error{WriteFailed}!void {
        c.output.flush() catch return error.WriteFailed;
    }

    /// The TLS 1.3 key state a KeyUpdate has to go out with before the next
    /// record, or null when none is due, claiming
    /// the peer's request if there is one. The claim happens before the
    /// update is sent, so a request arriving in between stays set and is
    /// answered before the record after this one. A request is answered
    /// only when something is written, which §4.7.3 allows: a connection
    /// that never writes again never answers, and the peer is not blocked.
    /// Past `max_key_updates` there is no update (§4.7.3): a request is
    /// ignored and the keys stay until `seal` refuses them. TLS 1.2 has no
    /// KeyUpdate; its keys last until the sequence number runs out.
    fn claimKeyUpdate(c: *Connection) ?*const cipher.Tls13 {
        const keys = &c.write.keys.?;
        const tls13 = switch (keys.version) {
            .tls13 => |*tls13| tls13,
            .tls12 => return null,
        };
        const requested = c.shared.key_update_requested.load(.monotonic) and
            c.shared.key_update_requested.swap(false, .monotonic);
        if (c.write.key_updates >= max_key_updates) return null;
        return if (requested or keys.seq >= keys.recordLimit()) tls13 else null;
    }

    /// Moves the write keys to the next generation, after the KeyUpdate
    /// announcing it was sealed with the old ones.
    fn advanceWriteKeys(c: *Connection, tls13: *const cipher.Tls13) error{TlsInternalError}!void {
        c.write.keys.?.update(tls13) catch return error.TlsInternalError;
        c.write.key_updates += 1;
        c.shared.key_updates_sent.store(c.write.key_updates, .monotonic);
    }

    fn keyUpdateMessage(request: proto.KeyUpdateRequest) [key_update_msg_len]u8 {
        return .{ @intFromEnum(proto.HandshakeType.key_update), 0, 0, 1, @intFromEnum(request) };
    }

    /// Sends a KeyUpdate and moves the write keys to the next generation.
    fn sendKeyUpdate(c: *Connection, request: proto.KeyUpdateRequest, tls13: *const cipher.Tls13) WriteError!void {
        try c.writeRecord(.handshake, &keyUpdateMessage(request));
        try c.advanceWriteKeys(tls13);
    }

    /// See `Writer.requestKeyUpdate`.
    fn requestKeyUpdate(c: *Connection) WriteError!void {
        try c.checkWritable();
        const tls13 = switch (c.write.keys.?.version) {
            .tls13 => |*tls13| tls13,
            .tls12 => return,
        };
        if (c.write.key_updates >= max_key_updates) return;
        // Set before the request goes out, so the answer cannot be
        // read before it is.
        const awaited = c.shared.key_update_awaited.swap(true, .monotonic);
        const owed = c.shared.key_update_requested.swap(false, .monotonic);
        // A request of the peer's is answered with update_not_requested
        // (§4.6.3), not folded into a request of ours. With ours still
        // unanswered, that answer is all that goes out.
        if (owed or awaited) {
            try c.reserve(key_update_record_len);
            c.sendKeyUpdate(.update_not_requested, tls13) catch |err| return c.failWrite(err);
        }
        if (!awaited and c.write.key_updates < max_key_updates) {
            try c.reserve(key_update_record_len);
            c.sendKeyUpdate(.update_requested, tls13) catch |err| return c.failWrite(err);
        }
        c.output.flush() catch return error.WriteFailed;
    }

    /// Flushes `output` unless it has `len` bytes free, so that a record
    /// of that length is sealed into it with no transport write between.
    fn reserve(c: *Connection, len: usize) error{WriteFailed}!void {
        if (c.output.unusedCapacityLen() < len) c.output.flush() catch return error.WriteFailed;
    }

    /// The write side's state, with the read side's failure delivered
    /// first: its alert goes out and this direction fails too. Only after
    /// the handshake; the handshake sends its own alerts.
    fn checkWritable(c: *Connection) WriteError!void {
        assert(c.write.keys != null);
        switch (c.shared.write_state.load(.monotonic)) {
            .open => {},
            .closed => return error.TlsConnectionFailed,
            .failed => return error.TlsConnectionFailed,
        }
        if (c.write.closing) return error.TlsConnectionFailed;
        if (c.shared.read_state.load(.acquire) == .failed) {
            const read_error: Failure = @errorCast(@errorFromInt(c.shared.read_error.load(.monotonic)));
            const alert = c.shared.pending_alert.swap(0, .monotonic);
            if (alert != 0) {
                // This may land on an in-place writer's window; nothing
                // from it is sent anyway, the direction fails here.
                c.writeRecord(.alert, &@as(proto.Alert, @enumFromInt(alert)).encode()) catch {};
                c.output.flush() catch {};
            }
            c.shared.write_state.store(.failed, .release);
            return read_error;
        }
    }

    fn failWrite(c: *Connection, err: WriteError) WriteError {
        c.shared.write_state.store(.failed, .release);
        return err;
    }

    /// Where the next in-place record's plaintext goes: inside `output`'s
    /// unused capacity, after the header (and TLS 1.2 AES-GCM's explicit
    /// nonce), with room left for the trailer and, in TLS 1.3, for a
    /// KeyUpdate ahead of it. Empty when `output` needs flushing.
    fn payloadWindow(c: *Connection) []u8 {
        @setRuntimeSafety(true);
        const keys = &c.write.keys.?;
        const unused = c.output.unusedCapacitySlice();
        const offset = keys.payloadOffset();
        const reserved = offset + switch (keys.version) {
            .tls13 => seal_spill,
            .tls12 => keys.trailerLen(),
        };
        if (unused.len <= reserved) return unused[0..0];
        return unused[offset..][0..@min(cipher.max_plaintext_len, unused.len - reserved)];
    }

    /// Seals the first `len` bytes of `payloadWindow()` where they are, as
    /// one record. A KeyUpdate that is due goes ahead of it, with the
    /// plaintext moved up to make room.
    fn sealWindow(c: *Connection, len: usize) WriteError!void {
        @setRuntimeSafety(true);
        try c.checkWritable();
        const keys = &c.write.keys.?;
        const buf = c.output.unusedCapacitySlice();
        var at: usize = 0;
        if (c.claimKeyUpdate()) |tls13| {
            // TLS 1.3 only, so the plaintext starts right after the header.
            std.mem.copyBackwards(u8, buf[key_update_record_len + cipher.header_len ..][0..len], buf[cipher.header_len..][0..len]);
            const msg = keyUpdateMessage(.update_not_requested);
            buf[cipher.header_len..][0..msg.len].* = msg;
            keys.seal(buf[0..key_update_record_len], .handshake, msg.len) catch |err| return c.failWrite(err);
            c.advanceWriteKeys(tls13) catch |err| return c.failWrite(err);
            at = key_update_record_len;
        }
        if (len > 0) {
            keys.seal(buf[at..], .application_data, len) catch |err| return c.failWrite(err);
            at += keys.sealedLen(len);
        }
        c.output.advance(at);
    }

    /// Sends what is sealed so far. A transport failure leaves it
    /// buffered in `output`, for the next flush.
    fn flushWrite(c: *Connection) WriteError!void {
        try c.checkWritable();
        c.output.flush() catch return error.WriteFailed;
    }

    /// Sends close_notify and closes the write direction; later writes
    /// fail. Idempotent. If the read side has an alert pending, that goes
    /// out instead and both directions are failed. For the writing task,
    /// after its writer was flushed for the last time. When the transport
    /// fails, close_notify stays sealed in `output` and calling this again
    /// only flushes.
    pub fn close(c: *Connection) WriteError!void {
        switch (c.shared.write_state.load(.monotonic)) {
            .open => {},
            .closed => return,
            .failed => return error.TlsConnectionFailed,
        }
        if (!c.write.closing) {
            try c.checkWritable();
            const alert = proto.Alert.close_notify.encode();
            try c.reserve(c.write.keys.?.sealedLen(alert.len));
            c.writeRecord(.alert, &alert) catch |err| return c.failWrite(err);
            c.write.closing = true;
        }
        c.output.flush() catch return error.WriteFailed;
        c.shared.write_state.store(.closed, .release);
    }

    /// Copies the start of `header` then `data` (the last element `splat`
    /// times) into `dest`, as much as fits.
    fn gather(dest: []u8, header: []const u8, data: []const []const u8, splat: usize) void {
        @setRuntimeSafety(true);
        var i = copyPrefix(dest, header);
        for (data[0 .. data.len - 1]) |bytes| {
            if (i == dest.len) return;
            i += copyPrefix(dest[i..], bytes);
        }
        const pattern = data[data.len - 1];
        if (pattern.len == 1) {
            @memset(dest[i..], pattern[0]);
            return;
        }
        var remaining = splat;
        while (i < dest.len) : (remaining -= 1) {
            assert(remaining > 0);
            i += copyPrefix(dest[i..], pattern);
        }
    }

    fn copyPrefix(dest: []u8, src: []const u8) usize {
        @setRuntimeSafety(true);
        const len = @min(dest.len, src.len);
        @memcpy(dest[0..len], src[0..len]);
        return len;
    }

    pub const Writer = struct {
        conn: *Connection,
        interface: Io.Writer,
        /// Why the last write failed: a `Failure` of the connection, the
        /// read side's included since its alert goes out this way, or
        /// `WriteFailed` when the transport writer failed and its own
        /// error says how. That one does not end the connection: what was
        /// sealed stays in the transport's buffer for the next flush, and
        /// what the in-place writer held unsealed is dropped.
        err: ?WriteError = null,

        fn init(c: *Connection, buffer: []u8) Writer {
            return .{
                .conn = c,
                .interface = .{
                    .vtable = &.{
                        .drain = drain,
                        .flush = flush,
                    },
                    .buffer = buffer,
                    .end = 0,
                },
            };
        }

        fn initInPlace(c: *Connection) Writer {
            return .{
                .conn = c,
                .interface = .{
                    .vtable = &.{
                        .drain = drainInPlace,
                        .flush = flush,
                        .rebase = rebaseInPlace,
                    },
                    .buffer = c.payloadWindow(),
                    .end = 0,
                },
            };
        }

        fn fail(self: *Writer, err: WriteError) Io.Writer.Error {
            self.err = err;
            if (self.interface.vtable.drain == drainInPlace) {
                // A transport write may have moved what is left in
                // `output`, and the window with it; what was in the window
                // and not yet sealed is dropped.
                self.interface.buffer = self.conn.payloadWindow();
                self.interface.end = 0;
            }
            return error.WriteFailed;
        }

        /// A window for a whole record, flushing `output` when it has no
        /// room for one.
        fn window(self: *Writer) Io.Writer.Error![]u8 {
            const c = self.conn;
            if (c.output.unusedCapacityLen() < output_buffer_len) {
                c.flushWrite() catch |err| return self.fail(err);
            }
            const w = c.payloadWindow();
            assert(w.len == cipher.max_plaintext_len);
            return w;
        }

        /// Records until the buffer is sent, the last taking as much of
        /// `data` as fits behind it.
        fn drain(w: *Io.Writer, data: []const []const u8, splat: usize) Io.Writer.Error!usize {
            const self: *Writer = @fieldParentPtr("interface", w);
            const buffered = w.buffered();
            var n: usize = 0;
            while (true) {
                const dest = self.window() catch |err| {
                    // What was sealed is written, whether or not it went out.
                    _ = w.consume(n);
                    return err;
                };
                const total = buffered.len - n + Io.Writer.countSplat(data, splat);
                const len = @min(dest.len, total);
                if (len == 0) break;
                gather(dest[0..len], buffered[n..], data, splat);
                self.conn.sealWindow(len) catch |err| return self.fail(err);
                n += len;
                if (n >= buffered.len) break;
            }
            return w.consume(n);
        }

        /// What is buffered is already in place: as much of `data` as fits
        /// joins it, and the window goes out as one record.
        fn drainInPlace(w: *Io.Writer, data: []const []const u8, splat: usize) Io.Writer.Error!usize {
            const self: *Writer = @fieldParentPtr("interface", w);
            const total = Io.Writer.countSplat(data, splat);
            const n = @min(w.buffer.len - w.end, total);
            gather(w.buffer[w.end..][0..n], "", data, splat);
            const len = w.end + n;
            if (len > 0) self.conn.sealWindow(len) catch |err| return self.fail(err);
            w.end = 0;
            // Sealed, the `n` bytes are written even if the transport fails
            // now; the next drain finds out again.
            w.buffer = self.window() catch |err| return if (n > 0) n else err;
            return n;
        }

        /// The default rebase would drain with the preserved bytes hidden,
        /// which seals the record ahead of them over their start. This
        /// saves them, seals, and moves them to the front of the next
        /// window.
        fn rebaseInPlace(w: *Io.Writer, preserve: usize, minimum_len: usize) Io.Writer.Error!void {
            @setRuntimeSafety(true);
            const self: *Writer = @fieldParentPtr("interface", w);
            const c = self.conn;
            while (w.buffer.len - w.end < minimum_len) {
                const keep = @min(preserve, w.end);
                const head = w.end - keep;
                if (head == 0) {
                    // Nothing to seal: the window is short because `output`
                    // holds earlier records. Send those and move what is
                    // buffered to the front of the full window that frees.
                    const tail = w.buffer[0..w.end];
                    c.flushWrite() catch |err| return self.fail(err);
                    const fresh = c.payloadWindow();
                    if (fresh.len - w.end < minimum_len) return self.fail(error.TlsInternalError);
                    @memmove(fresh[0..tail.len], tail);
                    w.buffer = fresh;
                    continue;
                }
                const tail = w.buffer[head..w.end];
                var spill: [seal_spill]u8 = undefined;
                const saved = @min(keep, spill.len);
                @memcpy(spill[0..saved], tail[0..saved]);
                try self.seal(head);
                if (w.buffer.len < keep) return self.fail(error.TlsInternalError);
                @memmove(w.buffer[saved..keep], tail[saved..]);
                @memcpy(w.buffer[0..saved], spill[0..saved]);
                w.end = keep;
            }
        }

        /// Seals the first `len` bytes of the window and takes the next one.
        fn seal(self: *Writer, len: usize) Io.Writer.Error!void {
            if (len > 0) self.conn.sealWindow(len) catch |err| return self.fail(err);
            self.interface.end = 0;
            self.interface.buffer = try self.window();
        }

        /// Sends what is buffered, then asks the peer to update its keys,
        /// updating ours first (§4.7.3). While an earlier request is still
        /// unanswered only our keys are updated: §4.7.3 allows one request
        /// at a time. Does nothing past `max_key_updates`, nor in TLS 1.2,
        /// which has no KeyUpdate. After a transport failure the update
        /// may have happened with only the flush left, and the writer may
        /// still be used; calling this again makes another update.
        pub fn requestKeyUpdate(self: *Writer) WriteError!void {
            self.interface.flush() catch return self.err.?;
            self.conn.requestKeyUpdate() catch |err| {
                self.fail(err) catch {};
                return err;
            };
        }

        /// Sends what is buffered, then close_notify; see
        /// `Connection.close`.
        pub fn close(self: *Writer) WriteError!void {
            // Once close_notify is sealed, only `output` is left to flush.
            if (!self.conn.write.closing) self.interface.flush() catch return self.err.?;
            self.conn.close() catch |err| {
                self.fail(err) catch {};
                return err;
            };
        }

        /// Seals what is buffered and sends everything sealed.
        fn flush(w: *Io.Writer) Io.Writer.Error!void {
            const self: *Writer = @fieldParentPtr("interface", w);
            if (w.end > 0) {
                if (w.vtable.drain == drainInPlace) {
                    try self.seal(w.end);
                } else {
                    _ = try drain(w, &.{""}, 1);
                }
            }
            self.conn.flushWrite() catch |err| return self.fail(err);
            // Flushed, `output` is empty and the next window is at its start.
            if (w.vtable.drain == drainInPlace) w.buffer = self.conn.payloadWindow();
        }
    };

    /// A cleartext writer with its own buffer; each drain copies into the
    /// next record. One per connection, for the writing task.
    pub fn writer(c: *Connection, buffer: []u8) Writer {
        assert(c.write.keys != null);
        return Writer.init(c, buffer);
    }

    /// A cleartext writer whose buffer is the next record's plaintext in
    /// `output`, so what is written is copied once, to where it is sealed.
    /// While it is in use nothing else may write to `output`: close it
    /// with `Writer.close`, not `Connection.close`.
    /// The transport writer must leave `output`'s unused capacity alone
    /// while draining (std's and zio's socket writers do). Its buffer moves
    /// with each record and must not be replaced. One per connection, for
    /// the writing task.
    pub fn writerInPlace(c: *Connection) Writer {
        assert(c.write.keys != null);
        return Writer.initInPlace(c);
    }
};

const testing = std.testing;
const testu = @import("../testu.zig");
const key_schedule = @import("key_schedule.zig");

/// The record protection a self-talk runs under.
const Mode = union(enum) {
    tls13: proto.CipherSuite,
    tls12: crypto.aead.Algorithm,
};

const every_mode = [_]Mode{
    .{ .tls13 = .aes_128_gcm_sha256 },
    .{ .tls13 = .aes_256_gcm_sha384 },
    .{ .tls13 = .chacha20_poly1305_sha256 },
} ++ if (proto.tls12_enabled) [_]Mode{
    .{ .tls12 = .aes_128_gcm },
    .{ .tls12 = .aes_256_gcm },
    .{ .tls12 = .chacha20_poly1305 },
} else [_]Mode{};

/// Both ends of a connection with pre-derived keys, over a loopback
/// socket: the peer runs as a concurrent task.
const SelfTalk = struct {
    io: Io,
    loopback: testu.Loopback,
    mode: Mode,
    /// How much of `End.output_buffer` the transport writer gets.
    output_len: usize = output_buffer_len,

    fn init(io: Io, mode: Mode) !SelfTalk {
        return .{ .io = io, .loopback = try testu.Loopback.init(io), .mode = mode };
    }

    fn deinit(self: *SelfTalk) void {
        self.loopback.deinit();
    }

    fn keys(self: *const SelfTalk, which: key_schedule.TrafficLabel) !cipher.Keys {
        switch (self.mode) {
            .tls13 => |suite| {
                const ks = key_schedule.KeySchedule.init(cipher.suiteHash(suite).?);
                return cipher.Keys.init(suite, ks.trafficSecret(which, "self-talk"));
            },
            .tls12 => |algorithm| {
                // A different key and IV for each direction.
                const key: [crypto.aead.max_key_length]u8 = @splat(@as(u8, @intFromEnum(which)) + 1);
                const iv: [crypto.aead.nonce_length]u8 = @splat(@as(u8, @intFromEnum(which)) + 0x41);
                return cipher.Keys.initTls12(algorithm, key[0..algorithm.keyLength()], iv[0..cipher.tls12FixedIvLen(algorithm)]);
            },
        }
    }

    /// One end, with its transport buffers; `deinit` before leaving the task.
    const End = struct {
        io: Io,
        stream: Io.net.Stream,
        input_buffer: [input_buffer_len]u8 = undefined,
        output_buffer: [2 * output_buffer_len]u8 = undefined,
        input: Io.net.Stream.Reader = undefined,
        output: Io.net.Stream.Writer = undefined,
        conn: Connection = undefined,

        fn setUp(end: *End, self: *const SelfTalk, side: proto.Side) !void {
            end.input = end.stream.reader(end.io, &end.input_buffer);
            end.output = end.stream.writer(end.io, end.output_buffer[0..self.output_len]);
            end.conn = Connection.init(&end.input.interface, &end.output.interface, side);
            end.conn.read.keys = try self.keys(if (side == .client) .server_application else .client_application);
            end.conn.write.keys = try self.keys(if (side == .client) .client_application else .server_application);
        }

        fn deinit(end: *End) void {
            end.conn.deinit();
            end.stream.close(end.io);
        }
    };

    fn client(self: *const SelfTalk, end: *End) !void {
        end.* = .{ .io = self.io, .stream = try self.loopback.connect() };
        errdefer end.stream.close(self.io);
        try end.setUp(self, .client);
    }

    fn server(self: *SelfTalk, end: *End) !void {
        end.* = .{ .io = self.io, .stream = try self.loopback.accept() };
        errdefer end.stream.close(self.io);
        try end.setUp(self, .server);
    }
};

test "application data both ways, then close_notify" {
    const io = testing.io;
    // With room for more than one record, the in-place writer's window
    // does not start at the front of the transport buffer.
    for ([_]usize{ output_buffer_len, 2 * output_buffer_len }) |output_len| for (every_mode) |mode| {
        var st = try SelfTalk.init(io, mode);
        defer st.deinit();
        st.output_len = output_len;

        const Peer = struct {
            fn run(s: *SelfTalk) !void {
                var end: SelfTalk.End = undefined;
                try s.server(&end);
                defer end.deinit();
                var rbuf: [256]u8 = undefined;
                var r = end.conn.reader(&rbuf);
                var w = end.conn.writerInPlace();
                while (try r.interface.takeDelimiter('\n')) |line| {
                    try w.interface.print("echo: {s}\n", .{line});
                    try w.interface.flush();
                }
                // The client's close_notify ends the stream; answer it.
                try end.conn.close();
            }
        };
        var peer = try io.concurrent(Peer.run, .{&st});
        defer peer.cancel(io) catch {};

        var end: SelfTalk.End = undefined;
        try st.client(&end);
        defer end.deinit();
        var rbuf: [256]u8 = undefined;
        var r = end.conn.reader(&rbuf);
        var wbuf: [64]u8 = undefined;
        var w = end.conn.writer(&wbuf);
        for (0..10) |i| {
            try w.interface.print("hello {d}\n", .{i});
            try w.interface.flush();
            var expected: [32]u8 = undefined;
            try testing.expectEqualStrings(try std.fmt.bufPrint(&expected, "echo: hello {d}", .{i}), (try r.interface.takeDelimiter('\n')).?);
        }
        try end.conn.close();
        try end.conn.close(); // idempotent
        try w.interface.writeAll("after close"); // buffered, so not sent yet
        try testing.expectError(error.WriteFailed, w.interface.flush());
        try testing.expectEqual(error.TlsConnectionFailed, w.err.?);
        try testing.expectEqual(null, try r.interface.takeDelimiter('\n'));
        try testing.expectEqual(null, r.err);
        try testing.expectEqual(State.closed, end.conn.shared.read_state.load(.monotonic));
        try peer.await(io);
    };
}

test "large transfers through both writers, with small and swapped reader buffers" {
    for ([_]Mode{ .{ .tls13 = .aes_128_gcm_sha256 }, .{ .tls12 = .aes_128_gcm }, .{ .tls12 = .chacha20_poly1305 } }) |mode| {
        if (mode == .tls12 and !proto.tls12_enabled) continue;
        try largeTransfer(mode);
    }
}

fn largeTransfer(mode: Mode) !void {
    const io = testing.io;
    var st = try SelfTalk.init(io, mode);
    defer st.deinit();
    const total = 300 * 1024;

    const Peer = struct {
        fn run(s: *SelfTalk) !void {
            var end: SelfTalk.End = undefined;
            try s.server(&end);
            defer end.deinit();
            // A tiny reader buffer: every record is opened in place and
            // handed out in pieces.
            var rbuf: [100]u8 = undefined;
            var r = end.conn.reader(&rbuf);
            var w = end.conn.writerInPlace();
            var received: usize = 0;
            var next: u8 = 0;
            while (received < total) {
                const chunk = r.interface.peekGreedy(1) catch |err| {
                    std.debug.print("peer read failed: {?}\n", .{r.err});
                    return err;
                };
                for (chunk) |b| {
                    try testing.expectEqual(next, b);
                    next +%= 1;
                }
                received += chunk.len;
                r.interface.toss(chunk.len);
                // Echo in odd-sized writes so records fill at odd points.
                try w.interface.writeAll(chunk);
            }
            try w.interface.flush();
            try end.conn.close();
        }
    };
    var peer = try io.concurrent(Peer.run, .{&st});
    defer peer.cancel(io) catch {};

    var end: SelfTalk.End = undefined;
    try st.client(&end);
    defer end.deinit();
    var w = end.conn.writerInPlace();
    const Sender = struct {
        fn run(wr: *Io.Writer) !void {
            var pattern: [7919]u8 = undefined;
            var next: u8 = 0;
            var sent: usize = 0;
            while (sent < total) {
                const n = @min(pattern.len, total - sent);
                for (pattern[0..n]) |*b| {
                    b.* = next;
                    next +%= 1;
                }
                try wr.writeAll(pattern[0..n]);
                sent += n;
            }
            try wr.flush();
        }
    };
    var sender = try io.concurrent(Sender.run, .{&w.interface});
    defer sender.cancel(io) catch {};

    // Read back through a big buffer first (records decrypt straight into
    // it), then swap to a small one mid-stream, as an application may.
    var big: [64 * 1024]u8 = undefined;
    var small: [1024]u8 = undefined;
    var r = end.conn.reader(&big);
    var received: usize = 0;
    var next: u8 = 0;
    while (received < total) {
        if (received > total / 2 and r.interface.buffer.ptr == &big) {
            const buffered = r.interface.buffered();
            @memcpy(small[0..buffered.len], buffered);
            r.interface.buffer = &small;
            r.interface.seek = 0;
            r.interface.end = buffered.len;
        }
        const chunk = try r.interface.peekGreedy(1);
        for (chunk) |b| {
            try testing.expectEqual(next, b);
            next +%= 1;
        }
        received += chunk.len;
        r.interface.toss(chunk.len);
    }
    try sender.await(io);
    try testing.expectEqual(error.EndOfStream, r.interface.peekGreedy(1));
    try end.conn.close();
    try peer.await(io);
}

test "key updates from both sides" {
    const io = testing.io;
    var st = try SelfTalk.init(io, .{ .tls13 = .chacha20_poly1305_sha256 });
    defer st.deinit();

    const Peer = struct {
        fn run(s: *SelfTalk) !void {
            var end: SelfTalk.End = undefined;
            try s.server(&end);
            defer end.deinit();
            var rbuf: [256]u8 = undefined;
            var r = end.conn.reader(&rbuf);
            var w = end.conn.writer(&.{});
            var count: usize = 0;
            while (try r.interface.takeDelimiter('\n')) |line| {
                try w.interface.writeAll(line);
                try w.interface.writeByte('\n');
                try w.interface.flush();
                count += 1;
                if (count == 2) try w.requestKeyUpdate();
            }
            try end.conn.close();
        }
    };
    var peer = try io.concurrent(Peer.run, .{&st});
    defer peer.cancel(io) catch {};

    var end: SelfTalk.End = undefined;
    try st.client(&end);
    defer end.deinit();
    var rbuf: [256]u8 = undefined;
    var r = end.conn.reader(&rbuf);
    var w = end.conn.writerInPlace();
    const write_gen0 = end.conn.write.keys.?.version.tls13.secret;
    const read_gen0 = end.conn.read.keys.?.version.tls13.secret;
    for (0..6) |i| {
        if (i == 4) try w.requestKeyUpdate();
        try w.interface.print("message {d}\n", .{i});
        try w.interface.flush();
        var expected: [32]u8 = undefined;
        try testing.expectEqualStrings(try std.fmt.bufPrint(&expected, "message {d}", .{i}), (try r.interface.takeDelimiter('\n')).?);
    }
    // The peer's request after its second reply rotated our write keys
    // before message 3 went out; our request before message 4 rotated
    // them again, and the peer's answer rotated its write keys, our read
    // keys, twice in all.
    try testing.expect(!std.mem.eql(u8, write_gen0.slice(), end.conn.write.keys.?.version.tls13.secret.slice()));
    try testing.expect(!std.mem.eql(u8, read_gen0.slice(), end.conn.read.keys.?.version.tls13.secret.slice()));
    const expected_write = key_schedule.nextTrafficSecret(.sha256, &key_schedule.nextTrafficSecret(.sha256, &write_gen0));
    try testing.expectEqualSlices(u8, expected_write.slice(), end.conn.write.keys.?.version.tls13.secret.slice());
    try end.conn.close();
    try peer.await(io);
}

test "past the key update cap a sender ignores requests and keeps its keys" {
    const io = testing.io;
    var st = try SelfTalk.init(io, .{ .tls13 = .aes_128_gcm_sha256 });
    defer st.deinit();

    const Peer = struct {
        fn run(s: *SelfTalk) !void {
            var end: SelfTalk.End = undefined;
            try s.server(&end);
            defer end.deinit();
            var rbuf: [256]u8 = undefined;
            var r = end.conn.reader(&rbuf);
            var w = end.conn.writer(&.{});
            try w.requestKeyUpdate();
            try w.interface.writeAll("ping\n");
            try w.interface.flush();
            try testing.expectEqualStrings("pong", (try r.interface.takeDelimiter('\n')).?);
            try testing.expectEqual(null, try r.interface.takeDelimiter('\n'));
        }
    };
    var peer = try io.concurrent(Peer.run, .{&st});
    defer peer.cancel(io) catch {};

    var end: SelfTalk.End = undefined;
    try st.client(&end);
    defer end.deinit();
    end.conn.write.key_updates = max_key_updates;
    const before = end.conn.write.keys.?.version.tls13.secret;
    var rbuf: [256]u8 = undefined;
    var r = end.conn.reader(&rbuf);
    var w = end.conn.writerInPlace();
    try testing.expectEqualStrings("ping", (try r.interface.takeDelimiter('\n')).?);
    try w.requestKeyUpdate(); // nothing happens at the cap
    try w.interface.writeAll("pong\n");
    try w.interface.flush();
    try testing.expectEqualSlices(u8, before.slice(), end.conn.write.keys.?.version.tls13.secret.slice());
    try testing.expectEqual(max_key_updates, end.conn.write.key_updates);
    try end.conn.close();
    try peer.await(io);
}

test "a header that rules a record out is refused without its body" {
    const Case = struct {
        header: [cipher.header_len]u8,
        tls13_keys: bool = false,
        ccs: Connection.CcsMode = .refuse,
        err: Connection.ReadRecordError,
    };
    const handshake = @intFromEnum(proto.ContentType.handshake);
    const ccs = @intFromEnum(proto.ContentType.change_cipher_spec);
    const cases = [_]Case{
        .{ .header = .{ 0x80, 0x2e, 0x01, 0x03, 0x03 }, .err = error.TlsUnexpectedMessage },
        .{ .header = .{ @intFromEnum(proto.ContentType.application_data), 3, 3, 0, 32 }, .err = error.TlsUnexpectedMessage },
        .{ .header = .{ handshake, 3, 3, 0, 0 }, .err = error.TlsUnexpectedMessage },
        .{ .header = .{ handshake, 3, 3, 0x40, 0x01 }, .err = error.TlsRecordOverflow },
        .{ .header = .{ handshake, 3, 3, 0, 32 }, .tls13_keys = true, .err = error.TlsUnexpectedMessage },
        .{ .header = .{ ccs, 3, 3, 0, 1 }, .err = error.TlsUnexpectedMessage },
        .{ .header = .{ ccs, 3, 3, 0, 2 }, .ccs = .drop, .err = error.TlsUnexpectedMessage },
        .{ .header = .{ ccs, 3, 3, 0, 2 }, .ccs = .deliver, .err = error.TlsIllegalParameter },
    };
    for (cases) |case| {
        var input_buffer: [input_buffer_len]u8 = undefined;
        input_buffer[0..cipher.header_len].* = case.header;
        var output_buffer: [output_buffer_len]u8 = undefined;
        var input: Io.Reader = .fixed(&input_buffer);
        // Only the header: waiting for the body would end as truncated.
        input.end = cipher.header_len;
        var discard: Io.Writer.Discarding = .init(&output_buffer);
        var conn = Connection.init(&input, &discard.writer, .client);
        defer conn.deinit();
        conn.read.ccs = case.ccs;
        if (case.tls13_keys) {
            const ks = key_schedule.KeySchedule.init(cipher.suiteHash(.aes_128_gcm_sha256).?);
            conn.read.keys = try cipher.Keys.init(.aes_128_gcm_sha256, ks.trafficSecret(.server_application, "header"));
        }
        try testing.expectError(case.err, conn.readRecord(null));
    }
}

/// A transport writer that, while failing, sends a few bytes of what is
/// buffered before each failure.
const TestSink = struct {
    failing: bool = true,
    sent: [4 * output_buffer_len]u8 = undefined,
    len: usize = 0,
    writer: Io.Writer,

    fn init(buffer: []u8) TestSink {
        return .{ .writer = .{ .vtable = &.{ .drain = drain }, .buffer = buffer } };
    }

    fn drain(w: *Io.Writer, data: []const []const u8, splat: usize) Io.Writer.Error!usize {
        const self: *TestSink = @fieldParentPtr("writer", w);
        if (self.failing) {
            const some = @min(w.end, 7);
            self.put(w.buffered()[0..some]);
            _ = w.consume(some);
            return error.WriteFailed;
        }
        self.put(w.buffered());
        var n: usize = 0;
        for (data[0 .. data.len - 1]) |d| {
            self.put(d);
            n += d.len;
        }
        for (0..splat) |_| self.put(data[data.len - 1]);
        n += data[data.len - 1].len * splat;
        return w.consume(w.end + n);
    }

    fn put(self: *TestSink, bytes: []const u8) void {
        @memcpy(self.sent[self.len..][0..bytes.len], bytes);
        self.len += bytes.len;
    }

    /// Decrypts what was sent, up to close_notify.
    fn received(self: *TestSink, secret: anytype) ![]u8 {
        var input: Io.Reader = .fixed(&self.sent);
        input.end = self.len;
        var output_buffer: [output_buffer_len]u8 = undefined;
        var output: Io.Writer = .fixed(&output_buffer);
        var peer = Connection.init(&input, &output, .server);
        defer peer.deinit();
        peer.read.keys = try cipher.Keys.init(.aes_128_gcm_sha256, secret);
        var rbuf: [64]u8 = undefined;
        var r = peer.reader(&rbuf);
        return r.interface.allocRemaining(testing.allocator, .unlimited);
    }
};

test "after a transport failure, what was sealed goes out with the next flush" {
    const ks = key_schedule.KeySchedule.init(cipher.suiteHash(.aes_128_gcm_sha256).?);
    const secret = ks.trafficSecret(.client_application, "retry");
    for ([_]bool{ false, true }) |in_place| {
        var input_buffer: [input_buffer_len]u8 = undefined;
        var input: Io.Reader = .fixed(&input_buffer);
        input.end = 0;
        var output_buffer: [output_buffer_len]u8 = undefined;
        var sink: TestSink = .init(&output_buffer);
        var conn = Connection.init(&input, &sink.writer, .client);
        defer conn.deinit();
        conn.write.keys = try cipher.Keys.init(.aes_128_gcm_sha256, secret);

        var wbuf: [64]u8 = undefined;
        var w = if (in_place) conn.writerInPlace() else conn.writer(&wbuf);
        try w.interface.writeAll("hello");
        try testing.expectError(error.WriteFailed, w.interface.flush());
        try testing.expectEqual(error.WriteFailed, w.err.?);
        sink.failing = false;
        try w.interface.flush();
        // The KeyUpdate is sealed and only its flush fails; the writer
        // goes on after it, its next record under the new keys.
        sink.failing = true;
        try testing.expectError(error.WriteFailed, w.requestKeyUpdate());
        try w.interface.writeAll(" world");
        try testing.expectError(error.WriteFailed, w.interface.flush());
        sink.failing = false;
        try w.interface.flush();
        sink.failing = true;
        try testing.expectError(error.WriteFailed, w.close());
        try testing.expectError(error.WriteFailed, w.close());
        // As under cancel protection in a defer, once the transport works.
        sink.failing = false;
        try w.close();
        try w.close();
        w.interface.writeAll("late") catch {};
        try testing.expectError(error.WriteFailed, w.interface.flush());
        try testing.expectEqual(error.TlsConnectionFailed, w.err.?);

        const got = try sink.received(secret);
        defer testing.allocator.free(got);
        try testing.expectEqualStrings("hello world", got);
    }
}

test "an in-place write that fills a record counts it as written when the flush after it fails" {
    const ks = key_schedule.KeySchedule.init(cipher.suiteHash(.aes_128_gcm_sha256).?);
    const secret = ks.trafficSecret(.client_application, "retry");
    var input_buffer: [input_buffer_len]u8 = undefined;
    var input: Io.Reader = .fixed(&input_buffer);
    input.end = 0;
    var output_buffer: [output_buffer_len]u8 = undefined;
    var sink: TestSink = .init(&output_buffer);
    var conn = Connection.init(&input, &sink.writer, .client);
    defer conn.deinit();
    conn.write.keys = try cipher.Keys.init(.aes_128_gcm_sha256, secret);

    var data: [cipher.max_plaintext_len + 10]u8 = undefined;
    for (&data, 0..) |*b, i| b.* = @truncate(i);
    var w = conn.writerInPlace();
    var sent: usize = 0;
    while (sent < data.len) {
        sent += w.interface.write(data[sent..]) catch {
            // The app retries what was not written, once the transport works.
            try testing.expect(sink.failing);
            sink.failing = false;
            continue;
        };
    }
    try w.interface.flush();
    try conn.close();

    const got = try sink.received(secret);
    defer testing.allocator.free(got);
    try testing.expectEqualSlices(u8, &data, got);
}

test "post-handshake messages split across records and sharing them" {
    const io = testing.io;
    var st = try SelfTalk.init(io, .{ .tls13 = .aes_128_gcm_sha256 });
    defer st.deinit();

    const nst = @intFromEnum(proto.HandshakeType.new_session_ticket);
    const ku = @intFromEnum(proto.HandshakeType.key_update);
    const Peer = struct {
        fn run(s: *SelfTalk) !void {
            var end: SelfTalk.End = undefined;
            try s.server(&end);
            defer end.deinit();
            // A ticket in three pieces, the header itself split and a
            // user_canceled between the first two; then a KeyUpdate that
            // starts in the ticket's last record and ends a record of its
            // own; then a ticket and a KeyUpdate whole in one record.
            const records = [_][]const u8{
                &.{ nst, 0 },
                &.{ 0, 14, 1, 2, 3, 4, 5 },
                &.{ 6, 7, 8, 9, 10, 11, 12, 13, 14, ku, 0 },
                &.{ 0, 1, 0 },
            };
            for (records, 0..) |payload, i| {
                try end.conn.writeRecord(.handshake, payload);
                if (i == 0) try end.conn.writeRecord(.alert, &.{ 1, @intFromEnum(proto.Alert.user_canceled) });
            }
            try end.conn.advanceWriteKeys(&end.conn.write.keys.?.version.tls13);
            try end.conn.writeRecord(.handshake, &[_]u8{ nst, 0, 0, 14 } ++ @as([14]u8, @splat(0)) ++ [_]u8{ ku, 0, 0, 1, 0 });
            try end.conn.advanceWriteKeys(&end.conn.write.keys.?.version.tls13);
            try end.conn.writeRecord(.application_data, "hi\n");
            try end.conn.flushOutput();
        }
    };
    var peer = try io.concurrent(Peer.run, .{&st});
    defer peer.cancel(io) catch {};

    var end: SelfTalk.End = undefined;
    try st.client(&end);
    defer end.deinit();
    const read_gen0 = end.conn.read.keys.?.version.tls13.secret;
    var rbuf: [256]u8 = undefined;
    var r = end.conn.reader(&rbuf);
    try testing.expectEqualStrings("hi", (try r.interface.takeDelimiter('\n')).?);
    const expected = key_schedule.nextTrafficSecret(.sha256, &key_schedule.nextTrafficSecret(.sha256, &read_gen0));
    try testing.expectEqualSlices(u8, expected.slice(), end.conn.read.keys.?.version.tls13.secret.slice());
    try testing.expectEqual(0, end.conn.read.message.len);
    try peer.await(io);
}

test "only one KeyUpdate request is outstanding at a time" {
    const io = testing.io;
    var st = try SelfTalk.init(io, .{ .tls13 = .aes_128_gcm_sha256 });
    defer st.deinit();

    const ku = @intFromEnum(proto.HandshakeType.key_update);
    const Peer = struct {
        fn expectKeyUpdate(end: *SelfTalk.End, request: proto.KeyUpdateRequest) !void {
            const record = try end.conn.readRecord(null);
            try testing.expectEqual(proto.ContentType.handshake, record.content_type);
            try testing.expectEqualSlices(u8, &.{ ku, 0, 0, 1, @intFromEnum(request) }, record.payload);
            try end.conn.handlePostHandshake(record.payload);
        }

        fn run(s: *SelfTalk) !void {
            var end: SelfTalk.End = undefined;
            try s.server(&end);
            defer end.deinit();
            // The second request waits on an answer to the first, so it
            // only updates the client's keys.
            try expectKeyUpdate(&end, .update_requested);
            try expectKeyUpdate(&end, .update_not_requested);
            // Our KeyUpdate lets the client ask again.
            try end.conn.sendKeyUpdate(.update_not_requested, &end.conn.write.keys.?.version.tls13);
            try end.conn.writeRecord(.application_data, "go\n");
            try end.conn.flushOutput();
            try expectKeyUpdate(&end, .update_requested);
        }
    };
    var peer = try io.concurrent(Peer.run, .{&st});
    defer peer.cancel(io) catch {};

    var end: SelfTalk.End = undefined;
    try st.client(&end);
    defer end.deinit();
    try end.conn.requestKeyUpdate();
    try end.conn.requestKeyUpdate();
    var rbuf: [256]u8 = undefined;
    var r = end.conn.reader(&rbuf);
    try testing.expectEqualStrings("go", (try r.interface.takeDelimiter('\n')).?);
    try end.conn.requestKeyUpdate();
    try peer.await(io);
}

test "a bad record fails the reader, and the writer sends the alert" {
    const io = testing.io;
    var st = try SelfTalk.init(io, .{ .tls13 = .aes_256_gcm_sha384 });
    defer st.deinit();

    const Peer = struct {
        fn run(s: *SelfTalk) !void {
            var end: SelfTalk.End = undefined;
            try s.server(&end);
            defer end.deinit();
            var rbuf: [256]u8 = undefined;
            var r = end.conn.reader(&rbuf);
            var w = end.conn.writerInPlace();
            try w.interface.writeAll("fine\n");
            try w.interface.flush();
            // Corrupt the next record on the wire: seal it, then flip a bit.
            const keys = &end.conn.write.keys.?;
            const rec = try end.output.interface.writableSliceGreedy(keys.sealedLen(5));
            rec[keys.payloadOffset()..][0..5].* = "oops\n".*;
            try keys.seal(rec[0..keys.sealedLen(5)], .application_data, 5);
            rec[keys.payloadOffset() + 2] ^= 0x40;
            end.output.interface.advance(keys.sealedLen(5));
            try end.output.interface.flush();
            // The client's reader fails and its writer sends bad_record_mac.
            try testing.expectError(error.ReadFailed, r.interface.takeDelimiter('\n'));
            try testing.expectEqual(error.TlsAlertBadRecordMac, r.err.?);
            try w.interface.writeAll("more\n");
            try testing.expectError(error.WriteFailed, w.interface.flush());
            try testing.expectEqual(error.TlsAlertBadRecordMac, w.err.?);
            try testing.expectError(error.TlsConnectionFailed, end.conn.close());
        }
    };
    var peer = try io.concurrent(Peer.run, .{&st});
    defer peer.cancel(io) catch {};

    var end: SelfTalk.End = undefined;
    try st.client(&end);
    defer end.deinit();
    var rbuf: [256]u8 = undefined;
    var r = end.conn.reader(&rbuf);
    var w = end.conn.writer(&.{});
    try testing.expectEqualStrings("fine", (try r.interface.takeDelimiter('\n')).?);
    try testing.expectError(error.ReadFailed, r.interface.takeDelimiter('\n'));
    try testing.expectEqual(error.TlsBadRecordMac, r.err.?);
    try testing.expectError(error.ReadFailed, r.interface.takeDelimiter('\n'));
    try testing.expectEqual(error.TlsConnectionFailed, r.err.?);
    // The writer learns of it, sends the alert, and fails with the cause.
    try testing.expectError(error.WriteFailed, w.interface.writeAll("x")); // no buffer: drains at once
    try testing.expectEqual(error.TlsBadRecordMac, w.err.?);
    try testing.expectEqual(State.failed, end.conn.shared.write_state.load(.monotonic));
    try peer.await(io);
}

test "transport ending without close_notify: clean at a record boundary, truncated inside one" {
    const io = testing.io;
    for ([_]bool{ false, true }) |strict| {
        var st = try SelfTalk.init(io, .{ .tls13 = .aes_128_gcm_sha256 });
        defer st.deinit();

        const Peer = struct {
            fn run(s: *SelfTalk, cut: bool) !void {
                var end: SelfTalk.End = undefined;
                try s.server(&end);
                defer end.deinit();
                var w = end.conn.writerInPlace();
                try w.interface.writeAll("whole record\n");
                try w.interface.flush();
                if (cut) {
                    const keys = &end.conn.write.keys.?;
                    const rec = try end.output.interface.writableSliceGreedy(keys.sealedLen(4));
                    rec[keys.payloadOffset()..][0..4].* = "half".*;
                    try keys.seal(rec[0..keys.sealedLen(4)], .application_data, 4);
                    end.output.interface.advance(keys.sealedLen(4) - 3);
                    try end.output.interface.flush();
                }
                // Then just hang up.
            }
        };

        for ([_]bool{ false, true }) |cut| {
            var peer = try io.concurrent(Peer.run, .{ &st, cut });
            defer peer.cancel(io) catch {};

            var end: SelfTalk.End = undefined;
            try st.client(&end);
            defer end.deinit();
            end.conn.strict_close_notify = strict;
            var rbuf: [256]u8 = undefined;
            var r = end.conn.reader(&rbuf);
            try testing.expectEqualStrings("whole record", (try r.interface.takeDelimiter('\n')).?);
            if (cut or strict) {
                try testing.expectError(error.ReadFailed, r.interface.takeDelimiter('\n'));
                try testing.expectEqual(error.TlsConnectionTruncated, r.err.?);
            } else {
                try testing.expectEqual(null, try r.interface.takeDelimiter('\n'));
                // A half-close: writing goes on until the transport objects.
                try testing.expectEqual(State.open, end.conn.shared.write_state.load(.monotonic));
                end.conn.close() catch |err| try testing.expectEqual(error.WriteFailed, err);
            }
            try peer.await(io);
        }
    }
}

test "concurrent reading and writing tasks on both ends" {
    for ([_]Mode{ .{ .tls13 = .aes_128_gcm_sha256 }, .{ .tls12 = .aes_256_gcm } }) |mode| {
        if (mode == .tls12 and !proto.tls12_enabled) continue;
        try concurrentTasks(mode);
    }
}

fn concurrentTasks(mode: Mode) !void {
    const io = testing.io;
    var st = try SelfTalk.init(io, mode);
    defer st.deinit();
    const lines = 2000;

    const Tasks = struct {
        fn send(c: *Connection, tag: []const u8) !void {
            var w = c.writerInPlace();
            for (0..lines) |i| try w.interface.print("{s} {d}\n", .{ tag, i });
            try w.interface.flush();
            try c.close();
        }
        fn receive(c: *Connection, tag: []const u8) !void {
            var rbuf: [512]u8 = undefined;
            var r = c.reader(&rbuf);
            var count: usize = 0;
            while (try r.interface.takeDelimiter('\n')) |line| {
                var expected: [32]u8 = undefined;
                try testing.expectEqualStrings(try std.fmt.bufPrint(&expected, "{s} {d}", .{ tag, count }), line);
                count += 1;
            }
            try testing.expectEqual(lines, count);
        }
        fn peer(s: *SelfTalk) !void {
            var end: SelfTalk.End = undefined;
            try s.server(&end);
            defer end.deinit();
            var sender = try s.io.concurrent(send, .{ &end.conn, "server" });
            defer sender.cancel(s.io) catch {};
            try receive(&end.conn, "client");
            try sender.await(s.io);
        }
    };
    var peer = try io.concurrent(Tasks.peer, .{&st});
    defer peer.cancel(io) catch {};

    var end: SelfTalk.End = undefined;
    try st.client(&end);
    defer end.deinit();
    var sender = try io.concurrent(Tasks.send, .{ &end.conn, "client" });
    defer sender.cancel(io) catch {};
    try Tasks.receive(&end.conn, "server");
    try sender.await(io);
    try peer.await(io);
}

test "TLS 1.2: warning alerts are ignored, KeyUpdate is not" {
    if (!proto.tls12_enabled) return error.SkipZigTest;
    const io = testing.io;
    var st = try SelfTalk.init(io, .{ .tls12 = .aes_128_gcm });
    defer st.deinit();

    const Peer = struct {
        fn run(s: *SelfTalk) !void {
            var end: SelfTalk.End = undefined;
            try s.server(&end);
            defer end.deinit();
            // Warnings in protected alert records, more than the cap over
            // the connection but never more than it in a row.
            for (0..max_warning_alerts + 2) |_| {
                try end.conn.writeRecord(.alert, &.{ 1, @intFromEnum(proto.Alert.unrecognized_name) });
                try end.conn.writeRecord(.application_data, "data\n");
            }
            try end.conn.flushOutput();
            var rbuf: [256]u8 = undefined;
            var r = end.conn.reader(&rbuf);
            try testing.expectEqualStrings("ack", (try r.interface.takeDelimiter('\n')).?);
            // A KeyUpdate has no place in TLS 1.2.
            try end.conn.writeRecord(.handshake, &.{ @intFromEnum(proto.HandshakeType.key_update), 0, 0, 1, 0 });
            try end.conn.flushOutput();
            try testing.expectError(error.ReadFailed, r.interface.takeDelimiter('\n'));
            try testing.expectEqual(error.TlsAlertUnexpectedMessage, r.err.?);
        }
    };
    var peer = try io.concurrent(Peer.run, .{&st});
    defer peer.cancel(io) catch {};

    var end: SelfTalk.End = undefined;
    try st.client(&end);
    defer end.deinit();
    var rbuf: [256]u8 = undefined;
    var r = end.conn.reader(&rbuf);
    var w = end.conn.writerInPlace();
    for (0..max_warning_alerts + 2) |_| {
        try testing.expectEqualStrings("data", (try r.interface.takeDelimiter('\n')).?);
    }
    // No KeyUpdate in TLS 1.2: asking for one does nothing.
    const seq = end.conn.write.keys.?.seq;
    try w.requestKeyUpdate();
    try testing.expectEqual(seq, end.conn.write.keys.?.seq);
    try w.interface.writeAll("ack\n");
    try w.interface.flush();
    try testing.expectError(error.ReadFailed, r.interface.takeDelimiter('\n'));
    try testing.expectEqual(error.TlsUnexpectedMessage, r.err.?);
    // The writer sends the alert and fails with the reader's cause.
    try w.interface.writeAll("x");
    try testing.expectError(error.WriteFailed, w.interface.flush());
    try testing.expectEqual(error.TlsUnexpectedMessage, w.err.?);
    try peer.await(io);
}

test "TLS 1.2: a fatal user_canceled ends the connection" {
    if (!proto.tls12_enabled) return error.SkipZigTest;
    const io = testing.io;
    var st = try SelfTalk.init(io, .{ .tls12 = .aes_128_gcm });
    defer st.deinit();

    const Peer = struct {
        fn run(s: *SelfTalk) !void {
            var end: SelfTalk.End = undefined;
            try s.server(&end);
            defer end.deinit();
            try end.conn.writeRecord(.alert, &.{ 1, @intFromEnum(proto.Alert.user_canceled) });
            try end.conn.writeRecord(.application_data, "data\n");
            try end.conn.writeRecord(.alert, &.{ 2, @intFromEnum(proto.Alert.user_canceled) });
            try end.conn.flushOutput();
        }
    };
    var peer = try io.concurrent(Peer.run, .{&st});
    defer peer.cancel(io) catch {};

    var end: SelfTalk.End = undefined;
    try st.client(&end);
    defer end.deinit();
    var rbuf: [256]u8 = undefined;
    var r = end.conn.reader(&rbuf);
    // At the warning level it is a note.
    try testing.expectEqualStrings("data", (try r.interface.takeDelimiter('\n')).?);
    try testing.expectError(error.ReadFailed, r.interface.takeDelimiter('\n'));
    try testing.expectEqual(error.TlsAlertUserCanceled, r.err.?);
    try peer.await(io);
}

test "TLS 1.2: HelloRequest is refused with no_renegotiation" {
    if (!proto.tls12_enabled) return error.SkipZigTest;
    const io = testing.io;
    var st = try SelfTalk.init(io, .{ .tls12 = .aes_256_gcm });
    defer st.deinit();

    const Peer = struct {
        fn run(s: *SelfTalk) !void {
            var end: SelfTalk.End = undefined;
            try s.server(&end);
            defer end.deinit();
            try end.conn.writeRecord(.handshake, &.{ @intFromEnum(proto.HandshakeType.hello_request), 0, 0, 0 });
            try end.conn.flushOutput();
            var rbuf: [256]u8 = undefined;
            var r = end.conn.reader(&rbuf);
            try testing.expectError(error.ReadFailed, r.interface.takeDelimiter('\n'));
            try testing.expectEqual(error.TlsAlertNoRenegotiation, r.err.?);
        }
    };
    var peer = try io.concurrent(Peer.run, .{&st});
    defer peer.cancel(io) catch {};

    var end: SelfTalk.End = undefined;
    try st.client(&end);
    defer end.deinit();
    var rbuf: [256]u8 = undefined;
    var r = end.conn.reader(&rbuf);
    var w = end.conn.writerInPlace();
    try testing.expectError(error.ReadFailed, r.interface.takeDelimiter('\n'));
    try testing.expectEqual(error.TlsNoRenegotiation, r.err.?);
    // The fatal alert goes out with the next write.
    try w.interface.writeAll("x");
    try testing.expectError(error.WriteFailed, w.interface.flush());
    try testing.expectEqual(error.TlsNoRenegotiation, w.err.?);
    try peer.await(io);
}

test "TLS 1.2: a fifth warning alert in a row is too many" {
    if (!proto.tls12_enabled) return error.SkipZigTest;
    const io = testing.io;
    var st = try SelfTalk.init(io, .{ .tls12 = .chacha20_poly1305 });
    defer st.deinit();

    const Peer = struct {
        fn run(s: *SelfTalk) !void {
            var end: SelfTalk.End = undefined;
            try s.server(&end);
            defer end.deinit();
            for (0..max_warning_alerts + 1) |_| {
                try end.conn.writeRecord(.alert, &.{ 1, @intFromEnum(proto.Alert.unrecognized_name) });
            }
            try end.conn.flushOutput();
        }
    };
    var peer = try io.concurrent(Peer.run, .{&st});
    defer peer.cancel(io) catch {};

    var end: SelfTalk.End = undefined;
    try st.client(&end);
    defer end.deinit();
    var rbuf: [256]u8 = undefined;
    var r = end.conn.reader(&rbuf);
    try testing.expectError(error.ReadFailed, r.interface.takeDelimiter('\n'));
    try testing.expectEqual(error.TlsUnexpectedMessage, r.err.?);
    try peer.await(io);
}
