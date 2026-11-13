//! A TLS connection on AWS-LC's libssl (`-Dimpl=libssl`), with the native
//! `Connection`'s API: `client` and `server` run the handshake over the
//! transport's reader and writer, and the connection hands out a cleartext
//! reader and writer.
//!
//! libssl never sees the transport. It reads ciphertext from one memory
//! BIO, `rbio`, and writes it to another, `wbio`. Transport I/O happens
//! only between libssl calls, in Zig, so a fiber may wait on it and move
//! to another thread: the reading task copies what the transport reader
//! holds into `rbio`, and the writing task moves what is in `wbio` to the
//! transport writer.
//!
//! What keeps this safe:
//!
//! - A transport failure never reaches libssl. A memory BIO takes all it
//!   is given, so libssl's writes always finish within the call: it never
//!   stops halfway through a record and never needs a call repeated.
//!   Plaintext counts as written once libssl has taken it; a failed
//!   transport write leaves the ciphertext in `wbio` or in the transport's
//!   buffer, for the next flush. The writing task empties `wbio` before
//!   each write, so it holds about a record at most.
//! - Each libssl call's result becomes a `Result`, and every place that
//!   makes a call switches over all of it, with no catch-all.
//! - One libssl object serves both directions, so the reading and the
//!   writing task take turns at it under `mutex`. Nothing under the mutex
//!   waits: it covers one libssl call, which only computes, and our
//!   callbacks, which only compute too. AWS-LC's error queue is
//!   thread-local, so it is read and cleared under the mutex as well,
//!   before the fiber can move.
//!
//! As in the native implementation, the read side never writes to the
//! transport. libssl queues a KeyUpdate reply for the next write; the alert
//! for a failure found while reading waits in `wbio` for the write side,
//! which then fails with the same error.

const std = @import("std");
const Io = std.Io;
const c = @import("c");

const proto = @import("../protocol.zig");
const crypto = @import("../crypto.zig");
const config = @import("../config.zig");
const api = @import("../api.zig");
const policy = @import("../policy.zig");

const x509 = crypto.x509;

pub const Failure = api.Failure;
pub const ReadError = api.ReadError;
pub const WriteError = api.WriteError;
pub const State = api.State;
pub const HandshakeError = api.Error;

/// The same as the native implementation's, so that code sizing its
/// transport buffers for either works with both. libssl keeps buffers of
/// its own, so it would make do with less.
pub const input_buffer_len = api.input_buffer_len;
pub const output_buffer_len = api.output_buffer_len;

/// The most plaintext one SSL_write is given: one record's worth.
const max_plaintext_len = 16 * 1024;
/// The most copies of a short repeated pattern gathered into one record.
const splat_buffer_len = 1024;

/// The configuration, while the handshake runs, for the callbacks.
const Options = union(enum) {
    none,
    client: *const config.Client,
    server: *const config.Server,
};

const Op = enum { handshake, read, write, shutdown, key_update };

/// How a libssl call ended.
const Result = union(enum) {
    /// Done; the cleartext read or written, if any.
    ok: usize,
    /// It needs more of the transport's input.
    want_read,
    /// libssl could not write; a memory BIO never refuses, so this does
    /// not happen.
    want_write,
    /// It waits for the signer hook.
    want_private_key,
    /// The peer's close_notify came.
    closed,
    /// The connection is over, for this reason.
    failed: HandshakeError,
};

const WriteState = enum {
    open,
    /// close_notify is in `wbio` or the transport's buffer, maybe not yet
    /// sent.
    closing,
    closed,
    failed,
};

pub const Connection = struct {
    /// Ciphertext from the transport. The reading task's after the
    /// handshake.
    input: *Io.Reader,
    /// Ciphertext to the transport. The writing task's after the
    /// handshake.
    output: *Io.Writer,
    ssl: *c.SSL,
    /// Ciphertext for libssl to read and what it wrote, both memory BIOs
    /// owned by `ssl`.
    rbio: *c.BIO,
    wbio: *c.BIO,

    /// Serializes the libssl and BIO calls of the reading and the writing
    /// task and guards what they share, below. Held for one call at a
    /// time, never across transport I/O.
    mutex: Io.Mutex = .init,
    /// A read ran since the last write, so libssl may hold a KeyUpdate
    /// reply that only a write sends.
    write_owed: bool = false,
    /// The read side's failure: the write side sends its alert, then fails
    /// with it too.
    read_failure: ?Failure = null,
    /// A fatal alert libssl sent or received in the current call.
    alert_sent: ?proto.Alert = null,
    alert_received: ?proto.Alert = null,
    /// A failure one of our callbacks decided in the current call, which
    /// says more than the alert that goes out for it.
    callback_error: ?HandshakeError = null,
    /// Why the server found no certificate to present, kept from libssl's
    /// certificate callback, which can only send handshake_failure, to its
    /// server name callback, which runs next in the same call and sends
    /// the alert the native server sends.
    selection_error: ?HandshakeError = null,
    /// KeyUpdates sent and received, counted by libssl's message callback.
    /// Atomic so either task may read them while the other's call runs.
    key_updates_sent: std.atomic.Value(u64) = .init(0),
    key_updates_received: std.atomic.Value(u64) = .init(0),
    options: Options = .none,
    /// The certificate presented, while the handshake runs, and the
    /// signing its hook was asked for.
    certificate: ?*const config.CertKeyPair = null,
    signing: ?*Signing = null,

    /// The reading task's.
    read_state: State = .open,
    tracker: RecordTracker = .{},
    /// The writing task's.
    write_state: WriteState = .open,

    // What the handshake settled, as in the native `Connection`.

    /// The protocol agreed through ALPN, pointing into the configuration.
    alpn_protocol: ?[]const u8 = null,
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
    side: proto.Side,

    fn init(ctx: *c.SSL_CTX, input: *Io.Reader, output: *Io.Writer, side: proto.Side) error{OutOfMemory}!Connection {
        if (input.buffer.len < input_buffer_len) @panic("ztls: the transport reader's buffer is shorter than input_buffer_len");
        if (output.buffer.len < output_buffer_len) @panic("ztls: the transport writer's buffer is shorter than output_buffer_len");
        const ssl = c.SSL_new(ctx) orelse return error.OutOfMemory;
        errdefer c.SSL_free(ssl);
        const rbio = c.BIO_new(c.BIO_s_mem()) orelse return error.OutOfMemory;
        const wbio = c.BIO_new(c.BIO_s_mem()) orelse {
            _ = c.BIO_free(rbio);
            return error.OutOfMemory;
        };
        // The SSL takes both, and frees them with itself.
        c.SSL_set_bio(ssl, rbio, wbio);
        c.SSL_set_info_callback(ssl, infoCallback);
        c.SSL_set_msg_callback(ssl, messageCallback);
        // Everything is set on the SSL, not the shared SSL_CTX, and none of
        // it is needed once the handshake is done.
        c.SSL_set_shed_handshake_config(ssl, 1);
        return .{ .input = input, .output = output, .ssl = ssl, .rbio = rbio, .wbio = wbio, .side = side };
    }

    /// Frees libssl's state. Sends nothing; both tasks must be done.
    pub fn deinit(conn: *Connection) void {
        c.SSL_free(conn.ssl);
        if (conn.gpa) |gpa| {
            for (conn.peer_certificates) |der| gpa.free(der);
            gpa.free(conn.peer_certificates);
        }
        conn.* = undefined;
    }

    /// The name in SNI: what a client asked for, as the server saw it, or
    /// what the client sent (none for an IP literal).
    pub fn serverName(conn: *const Connection) ?[]const u8 {
        return if (conn.server_name_len == 0) null else conn.server_name_buf[0..conn.server_name_len];
    }

    /// KeyUpdates sent so far, our requests and our answers alike. An
    /// answer counts once libssl queues it, which may be before the
    /// writing task sends it.
    pub fn keyUpdatesSent(conn: *const Connection) u64 {
        return conn.key_updates_sent.load(.monotonic);
    }

    /// KeyUpdates received so far.
    pub fn keyUpdatesReceived(conn: *const Connection) u64 {
        return conn.key_updates_received.load(.monotonic);
    }

    fn setServerName(conn: *Connection, name: ?[]const u8) void {
        const n = name orelse "";
        // libssl refuses longer names.
        const len = @min(n.len, conn.server_name_buf.len);
        @memcpy(conn.server_name_buf[0..len], n[0..len]);
        conn.server_name_len = @intCast(len);
    }

    // libssl calls, all with `mutex` held

    /// Runs one libssl operation. `buf` is the cleartext to read into or
    /// write.
    fn call(conn: *Connection, op: Op, buf: []const u8) Result {
        conn.callback_error = null;
        conn.selection_error = null;
        conn.alert_sent = null;
        conn.alert_received = null;
        conn.bind();
        const ssl = conn.ssl;
        const len: c_int = @intCast(buf.len);
        const rc: c_int = switch (op) {
            .handshake => c.SSL_do_handshake(ssl),
            .read => c.SSL_read(ssl, @constCast(buf.ptr), len),
            .write => c.SSL_write(ssl, buf.ptr, len),
            .shutdown => c.SSL_shutdown(ssl),
            .key_update => keyUpdate(ssl),
        };
        const ok = switch (op) {
            .handshake, .read => rc > 0,
            // A write takes all of `buf`; an empty one returns 0.
            .write, .key_update => if (buf.len == 0) rc == 0 else rc > 0,
            // 0 once close_notify is out, 1 once the peer's came too.
            .shutdown => rc >= 0,
        };
        const result: Result = if (ok) .{ .ok = if (rc > 0) @intCast(rc) else 0 } else switch (c.SSL_get_error(ssl, rc)) {
            c.SSL_ERROR_WANT_READ => .want_read,
            c.SSL_ERROR_WANT_WRITE => .want_write,
            c.SSL_ERROR_WANT_PRIVATE_KEY_OPERATION => .want_private_key,
            c.SSL_ERROR_ZERO_RETURN => .closed,
            // Anything else ends the connection, SSL_ERROR_SYSCALL
            // included, which a memory BIO never gives libssl a reason
            // for.
            else => .{ .failed = conn.classify() },
        };
        // libssl's calls clear the queue on entry; empty it for others on
        // this thread.
        c.ERR_clear_error();
        return result;
    }

    /// Points the callbacks at this connection, which may have moved since
    /// the last call.
    fn bind(conn: *Connection) void {
        _ = c.SSL_set_ex_data(conn.ssl, globals_value.?.ex_index, conn);
    }

    /// Copies what the transport reader holds into `rbio`, for the next
    /// call to read. Only the reading task, or the handshake's, reads the
    /// transport.
    fn feed(conn: *Connection) error{OutOfMemory}!void {
        const bytes = conn.input.buffered();
        if (bytes.len == 0) return;
        if (c.BIO_write(conn.rbio, bytes.ptr, @intCast(bytes.len)) != @as(c_int, @intCast(bytes.len))) {
            c.ERR_clear_error();
            return error.OutOfMemory;
        }
        conn.tracker.feed(bytes);
        conn.input.toss(bytes.len);
    }

    /// Why the last call failed, best said first: our own callbacks'
    /// verdict, the peer's alert, what libssl found in a record, the alert
    /// it sent.
    fn classify(conn: *Connection) HandshakeError {
        if (conn.callback_error) |err| return err;
        if (conn.alert_received) |alert| {
            if (alert.toError()) |err| return err;
        }
        // The queue is cleared after the call anyway. A failed open puts
        // the AEAD's error ahead of libssl's.
        while (true) {
            const packed_error = c.ERR_get_error();
            if (packed_error == 0) break;
            if (reasonError(packed_error)) |err| return err;
        }
        if (conn.alert_sent) |alert| return localError(alert);
        return error.TlsInternalError;
    }

    /// Sends the alert the native implementation sends for `err`, unless
    /// libssl sent one in the last call, or `err` came from the peer.
    fn ensureAlert(conn: *Connection, err: anyerror) void {
        if (conn.alert_sent != null) return;
        const alert = proto.Alert.forLocalError(err) orelse return;
        conn.bind();
        // Refused once close_notify is out: nothing more can be said.
        _ = c.SSL_send_fatal_alert(conn.ssl, @intFromEnum(alert));
        c.ERR_clear_error();
    }

    // Moving ciphertext to the transport: the handshake's task or the
    // writing task only.

    /// Moves what libssl wrote from `wbio` into the transport writer,
    /// flushing that whenever it fills, and at the end too when `flush` is
    /// set. A transport failure leaves what was not sent where it is, for
    /// the next time.
    fn sendWritten(conn: *Connection, flush: bool) error{WriteFailed}!void {
        while (true) {
            lock(&conn.mutex);
            const space = conn.output.unusedCapacitySlice();
            const want = @min(c.BIO_pending(conn.wbio), space.len, std.math.maxInt(c_int));
            const got = if (want == 0) 0 else c.BIO_read(conn.wbio, space.ptr, @intCast(want));
            const left = c.BIO_pending(conn.wbio);
            unlock(&conn.mutex);
            // A memory BIO hands over what it holds.
            if (got != @as(c_int, @intCast(want))) @panic("ztls: a memory BIO failed to hand over its contents");
            conn.output.advance(want);
            if (left == 0) break;
            conn.output.flush() catch return error.WriteFailed;
        }
        if (flush) conn.output.flush() catch return error.WriteFailed;
    }

    /// Whether `wbio` holds something not yet moved to the transport.
    fn writtenPending(conn: *Connection) bool {
        return c.BIO_pending(conn.wbio) > 0;
    }

    // Handshake

    /// Runs the handshake to its end, with both of the transport's sides.
    fn runHandshake(conn: *Connection) HandshakeError!void {
        defer conn.dropSigning();
        while (true) {
            lock(&conn.mutex);
            const step: Result = if (conn.feed()) conn.call(.handshake, "") else |err| .{ .failed = err };
            switch (step) {
                .failed => |err| conn.ensureAlert(err),
                else => {},
            }
            unlock(&conn.mutex);
            switch (step) {
                .ok => return conn.sendWritten(true),
                .want_read => {
                    try conn.sendWritten(true);
                    try conn.input.fillMore();
                },
                .want_write => try conn.sendWritten(true),
                // The signer hook runs here, with the mutex released, and
                // may block or suspend.
                .want_private_key => conn.runSigner(),
                // The peer ended the connection: there is no one to tell.
                .closed => return error.EndOfStream,
                .failed => |err| {
                    // Best effort: the alert.
                    conn.sendWritten(true) catch {};
                    return err;
                },
            }
        }
    }

    /// Signs what `signCallback` asked for through the certificate's hook.
    /// A failure is reported when libssl collects the signature.
    fn runSigner(conn: *Connection) void {
        const job = conn.signing.?;
        const pair = conn.certificate.?;
        const signer = pair.signer.?;
        const signed = signer.sign(signer.context, &pair.key, job.algorithm, job.message, &job.signature_buf) catch return;
        // The hook's result has to be a slice of the buffer it was given;
        // anything else is its bug, not the peer's.
        const start = @intFromPtr(signed.ptr) -% @intFromPtr(&job.signature_buf);
        if (start > job.signature_buf.len or signed.len > job.signature_buf.len - start) return;
        job.signature = signed;
    }

    fn dropSigning(conn: *Connection) void {
        const job = conn.signing orelse return;
        const gpa = conn.optionsGpa();
        gpa.free(job.message);
        gpa.destroy(job);
        conn.signing = null;
    }

    fn optionsGpa(conn: *const Connection) std.mem.Allocator {
        return switch (conn.options) {
            .none => unreachable,
            .client => |opt| opt.gpa,
            .server => |opt| opt.gpa,
        };
    }

    /// Records what the handshake settled.
    fn finishHandshake(conn: *Connection, gpa: std.mem.Allocator, keep_peer_certificates: bool) error{OutOfMemory}!void {
        const ssl = conn.ssl;
        conn.version = @enumFromInt(c.SSL_version(ssl));
        if (c.SSL_get_current_cipher(ssl)) |current| conn.suite = @enumFromInt(c.SSL_CIPHER_get_protocol_id(current));
        const group = c.SSL_get_group_id(ssl);
        if (group != 0) conn.group = @enumFromInt(group);
        conn.retried = c.SSL_used_hello_retry_request(ssl) != 0;
        const scheme = c.SSL_get_peer_signature_algorithm(ssl);
        if (scheme != 0) conn.peer_signature_scheme = @enumFromInt(scheme);

        const chain = peerChain(ssl);
        if (chain.len > 0) {
            if (x509.Certificate.parseDer(chain.get(0))) |leaf_const| {
                var leaf = leaf_const;
                defer leaf.deinit();
                if (leaf.publicKey()) |key_const| {
                    var key = key_const;
                    conn.peer_key_type = key.key_type;
                    key.deinit();
                } else |_| {}
            } else |_| {}
        }
        if (keep_peer_certificates and chain.len > 0) {
            var copies: std.ArrayList([]const u8) = .empty;
            errdefer {
                for (copies.items) |der| gpa.free(der);
                copies.deinit(gpa);
            }
            try copies.ensureTotalCapacity(gpa, chain.len);
            for (0..chain.len) |i| copies.appendAssumeCapacity(try gpa.dupe(u8, chain.get(i)));
            conn.peer_certificates = try copies.toOwnedSlice(gpa);
            conn.gpa = gpa;
        }
    }

    // Read side

    /// Ends the read side with `err` for both tasks: the write side sends
    /// the alert and fails with `err` too. With `mutex` held.
    fn failRead(conn: *Connection, err: Failure) void {
        conn.read_state = .failed;
        conn.read_failure = err;
        conn.ensureAlert(err);
    }

    /// Decrypts into `dest` (not empty). Returns at least one byte, or
    /// `error.EndOfStream` at the end of the stream.
    fn readSome(conn: *Connection, dest: []u8) (ReadError || error{EndOfStream})!usize {
        switch (conn.read_state) {
            .open => {},
            .closed => return error.EndOfStream,
            .failed => return error.TlsConnectionFailed,
        }
        const len = @min(dest.len, std.math.maxInt(c_int));
        while (true) {
            lock(&conn.mutex);
            const step: Result = if (conn.feed()) conn.call(.read, dest[0..len]) else |err| .{ .failed = err };
            conn.write_owed = true;
            const failure: ?Failure = switch (step) {
                .ok, .want_read, .closed => null,
                // Neither can happen: a memory BIO takes all libssl writes,
                // and no key operation runs after the handshake.
                .want_write, .want_private_key => error.TlsInternalError,
                .failed => |err| asFailure(err),
            };
            if (failure) |err| conn.failRead(err);
            unlock(&conn.mutex);

            switch (step) {
                .ok => |n| return n,
                .closed => {
                    conn.read_state = .closed;
                    return error.EndOfStream;
                },
                .want_read => conn.input.fillMore() catch |err| switch (err) {
                    // Not the connection's failure: what was read stays
                    // buffered, and the read may be retried.
                    error.ReadFailed => return error.ReadFailed,
                    error.EndOfStream => {
                        // libssl asks for more only once it has taken all
                        // of `rbio`, so the tracker has seen what it read.
                        // Between records it is the end, unless the peer
                        // must say so with close_notify.
                        if (conn.tracker.atBoundary() and !conn.strict_close_notify) {
                            conn.read_state = .closed;
                            return error.EndOfStream;
                        }
                        lock(&conn.mutex);
                        conn.failRead(error.TlsConnectionTruncated);
                        unlock(&conn.mutex);
                        return error.TlsConnectionTruncated;
                    },
                },
                // The read side failed, as recorded above.
                .want_write, .want_private_key, .failed => return failure orelse error.TlsInternalError,
            }
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

        fn stream(r: *Io.Reader, w: *Io.Writer, limit: Io.Limit) Io.Reader.StreamError!usize {
            const self: *Reader = @fieldParentPtr("interface", r);
            const dest = limit.slice(try w.writableSliceGreedy(1));
            if (dest.len == 0) return 0;
            const n = self.conn.readSome(dest) catch |err| switch (err) {
                error.EndOfStream => return error.EndOfStream,
                else => |e| {
                    self.err = e;
                    return error.ReadFailed;
                },
            };
            w.advance(n);
            return n;
        }
    };

    /// The cleartext reader. `buffer` is an ordinary reader buffer that the
    /// application may swap at any time. One per connection, for the
    /// reading task.
    pub fn reader(conn: *Connection, buffer: []u8) Reader {
        return .{
            .conn = conn,
            .interface = .{
                .vtable = &.{ .stream = Reader.stream },
                .buffer = buffer,
                .seek = 0,
                .end = 0,
            },
        };
    }

    // Write side

    fn checkWritable(conn: *Connection) WriteError!void {
        switch (conn.write_state) {
            .open => {},
            .closing, .closed, .failed => return error.TlsConnectionFailed,
        }
    }

    fn failWrite(conn: *Connection, err: Failure) Failure {
        conn.write_state = .failed;
        return err;
    }

    /// The read side failed: its alert goes out, best effort, and this
    /// side fails with its error, as in the native implementation.
    fn takeReadFailure(conn: *Connection, err: Failure) Failure {
        conn.sendWritten(true) catch {};
        return conn.failWrite(err);
    }

    /// Runs one write-side libssl operation, which is done in one call:
    /// libssl never holds half a write that would have to be repeated. It
    /// runs with `wbio` empty, to keep that to about a record; moving
    /// earlier ciphertext out of it may fail on the transport, and then
    /// nothing was done.
    fn writeOp(conn: *Connection, op: Op, bytes: []const u8) WriteError!void {
        if (bytes.len > max_plaintext_len) @panic("ztls: more than a record's worth given to one write");
        while (true) {
            lock(&conn.mutex);
            if (conn.read_failure) |err| {
                unlock(&conn.mutex);
                return conn.takeReadFailure(err);
            }
            if (conn.writtenPending()) {
                unlock(&conn.mutex);
                try conn.sendWritten(false);
                continue;
            }
            const step = conn.call(op, bytes);
            switch (step) {
                .ok => if (op != .shutdown) {
                    conn.write_owed = false;
                },
                .failed => |err| conn.ensureAlert(err),
                else => {},
            }
            unlock(&conn.mutex);
            switch (step) {
                .ok => return,
                // None can happen: a memory BIO takes all libssl writes,
                // and none of these reads. libssl may hold half a write now, so the
                // direction is over.
                .want_read, .want_write, .want_private_key, .closed => return conn.failWrite(error.TlsInternalError),
                .failed => |err| {
                    conn.sendWritten(true) catch {};
                    return conn.failWrite(asFailure(err));
                },
            }
        }
    }

    /// Encrypts `bytes`, at most a record's worth, into `wbio`.
    fn writeRecord(conn: *Connection, bytes: []const u8) WriteError!void {
        try conn.checkWritable();
        try conn.writeOp(.write, bytes);
    }

    /// Sends everything encrypted, and what libssl has queued: a KeyUpdate
    /// reply goes out with an empty write.
    fn flushWrite(conn: *Connection) WriteError!void {
        try conn.checkWritable();
        lock(&conn.mutex);
        const owed = conn.write_owed;
        const read_failure = conn.read_failure;
        unlock(&conn.mutex);
        if (read_failure) |err| return conn.takeReadFailure(err);
        if (owed) try conn.writeOp(.write, "");
        conn.sendWritten(true) catch return error.WriteFailed;
    }

    /// Asks the peer to update its keys, updating ours, and sends the
    /// request. Does nothing in TLS 1.2, which has no KeyUpdate. After a
    /// transport failure the update may have happened with only the flush
    /// left; calling this again makes another update.
    fn requestKeyUpdate(conn: *Connection) WriteError!void {
        try conn.checkWritable();
        if (conn.version != .tls_1_3) return;
        try conn.writeOp(.key_update, "");
        conn.sendWritten(true) catch return error.WriteFailed;
    }

    /// Sends close_notify and closes the write direction; later writes
    /// fail. Idempotent. If the read side failed, its alert goes out
    /// instead and this fails with its error. For the writing task, after
    /// its writer was flushed for the last time. When the transport
    /// fails, close_notify stays encrypted and calling this again only
    /// sends it.
    pub fn close(conn: *Connection) WriteError!void {
        switch (conn.write_state) {
            .open => {
                try conn.writeOp(.shutdown, "");
                conn.write_state = .closing;
            },
            .closing => {},
            .closed => return,
            .failed => return error.TlsConnectionFailed,
        }
        conn.sendWritten(true) catch return error.WriteFailed;
        conn.write_state = .closed;
    }

    pub const Writer = struct {
        conn: *Connection,
        interface: Io.Writer,
        /// Why the last write failed: a `Failure` of the connection, the
        /// read side's included since its alert goes out this way, or
        /// `WriteFailed` when the transport writer failed and its own
        /// error says how. That one does not end the connection: what was
        /// encrypted waits for the next flush, and what was not is still
        /// in this writer, or was not taken from the caller.
        err: ?WriteError = null,

        fn fail(self: *Writer, err: WriteError) Io.Writer.Error {
            self.err = err;
            return error.WriteFailed;
        }

        /// Encrypts one record: from what is buffered when there is any,
        /// else from the start of `data`. Takes from the buffer and from
        /// `data` only what libssl took.
        fn drain(w: *Io.Writer, data: []const []const u8, splat: usize) Io.Writer.Error!usize {
            const self: *Writer = @fieldParentPtr("interface", w);
            const conn = self.conn;
            if (w.end > 0) {
                const n = @min(w.end, max_plaintext_len);
                conn.writeRecord(w.buffer[0..n]) catch |err| return self.fail(err);
                _ = w.consume(n);
                return 0;
            }
            for (data[0 .. data.len - 1]) |bytes| {
                if (bytes.len == 0) continue;
                const n = @min(bytes.len, max_plaintext_len);
                conn.writeRecord(bytes[0..n]) catch |err| return self.fail(err);
                return n;
            }
            const pattern = data[data.len - 1];
            if (pattern.len == 0 or splat == 0) return 0;
            if (splat == 1 or pattern.len > splat_buffer_len / 2) {
                const n = @min(pattern.len, max_plaintext_len);
                conn.writeRecord(pattern[0..n]) catch |err| return self.fail(err);
                return n;
            }
            // A short pattern repeated, padding say: as many copies as fit
            // a small buffer, in one record.
            var buf: [splat_buffer_len]u8 = undefined;
            const copies = @min(splat, buf.len / pattern.len);
            for (0..copies) |i| @memcpy(buf[i * pattern.len ..][0..pattern.len], pattern);
            const n = copies * pattern.len;
            conn.writeRecord(buf[0..n]) catch |err| return self.fail(err);
            return n;
        }

        /// Encrypts what is buffered and sends everything encrypted.
        fn flush(w: *Io.Writer) Io.Writer.Error!void {
            const self: *Writer = @fieldParentPtr("interface", w);
            while (w.end > 0) _ = try drain(w, &.{""}, 1);
            self.conn.flushWrite() catch |err| return self.fail(err);
        }

        /// Sends what is buffered, then asks the peer to update its keys,
        /// updating ours first. Does nothing in TLS 1.2.
        pub fn requestKeyUpdate(self: *Writer) WriteError!void {
            self.interface.flush() catch return self.err.?;
            self.conn.requestKeyUpdate() catch |err| {
                self.err = err;
                return err;
            };
        }

        /// Sends what is buffered, then close_notify; see
        /// `Connection.close`.
        pub fn close(self: *Writer) WriteError!void {
            // Once close_notify is encrypted, only sending it is left.
            if (self.conn.write_state == .open) self.interface.flush() catch return self.err.?;
            self.conn.close() catch |err| {
                self.err = err;
                return err;
            };
        }
    };

    /// A cleartext writer with its own buffer. One per connection, for the
    /// writing task. There is no `writerInPlace`: libssl encrypts in a
    /// buffer of its own, never in the transport's.
    pub fn writer(conn: *Connection, buffer: []u8) Writer {
        return .{
            .conn = conn,
            .interface = .{
                .vtable = &.{ .drain = Writer.drain, .flush = Writer.flush },
                .buffer = buffer,
                .end = 0,
            },
        };
    }
};

/// A KeyUpdate request. libssl requests nothing while a reply it owes is
/// queued, so that goes out first, with an empty write.
fn keyUpdate(ssl: *c.SSL) c_int {
    const flushed = c.SSL_write(ssl, "", 0);
    if (flushed != 0) return flushed;
    if (c.SSL_key_update(ssl, c.SSL_KEY_UPDATE_REQUESTED) != 1) return -1;
    return c.SSL_write(ssl, "", 0);
}

/// What libssl found wrong in a record, for the failures it may have sent
/// no alert for, as after our close_notify.
fn reasonError(packed_error: u32) ?HandshakeError {
    if ((packed_error >> 24) & 0xff != c.ERR_LIB_SSL) return null;
    return switch (packed_error & 0xfff) {
        c.SSL_R_DECRYPTION_FAILED_OR_BAD_RECORD_MAC => error.TlsBadRecordMac,
        c.SSL_R_ENCRYPTED_LENGTH_TOO_LONG, c.SSL_R_DATA_LENGTH_TOO_LONG => error.TlsRecordOverflow,
        c.SSL_R_UNEXPECTED_RECORD => error.TlsUnexpectedMessage,
        c.SSL_R_NO_RENEGOTIATION => error.TlsNoRenegotiation,
        c.SSL_R_EXCESSIVE_MESSAGE_SIZE => error.TlsIllegalParameter,
        else => null,
    };
}

// Setup

/// Runs the client side of a handshake over `input` and `output`.
pub fn client(input: *Io.Reader, output: *Io.Writer, options: config.Client) HandshakeError!Connection {
    try policy.checkClient(options);
    const g = try globals();
    var conn = try Connection.init(g.client_ctx, input, output, .client);
    errdefer conn.deinit();
    const ssl = conn.ssl;
    c.SSL_set_connect_state(ssl);

    const offers_tls12 = policy.offers(options, .tls_1_2);
    const offers_tls13 = policy.offers(options, .tls_1_3);
    try setVersions(ssl, if (offers_tls12) c.TLS1_2_VERSION else c.TLS1_3_VERSION, if (offers_tls13) c.TLS1_3_VERSION else c.TLS1_2_VERSION);
    try setCipherSuites(ssl, options.cipher_suites);
    try setPreferences(ssl, options.named_groups, options.signing_schemes, options.verify_schemes);
    // libssl holds every handshake message to this, but to no less than
    // 16 KiB.
    c.SSL_set_max_cert_list(ssl, options.max_handshake_message_len);

    var name_buf: [256]u8 = undefined;
    if (policy.sendsSni(options.host)) {
        const name = try terminated(&name_buf, options.host);
        if (c.SSL_set_tlsext_host_name(ssl, name) != 1) return error.TlsInternalError;
        conn.setServerName(options.host);
    }
    if (options.insecure_skip_verify) {
        c.SSL_set_custom_verify(ssl, c.SSL_VERIFY_NONE, null);
    } else {
        c.SSL_set_custom_verify(ssl, c.SSL_VERIFY_PEER, verifyCallback);
    }
    if (options.alpn_protocols.len > 0) try setAlpn(ssl, options.gpa, options.alpn_protocols);
    // The certificate is picked when the server asks for one.
    if (options.auth != null) c.SSL_set_cert_cb(ssl, clientCertificateCallback, null);

    conn.options = .{ .client = &options };
    conn.runHandshake() catch |err| {
        conn.options = .none;
        return err;
    };
    conn.options = .none;
    conn.alpn_protocol = selectedAlpn(ssl, options.alpn_protocols);
    conn.strict_close_notify = options.strict_close_notify;
    try conn.finishHandshake(options.gpa, options.keep_peer_certificates);
    return conn;
}

/// Runs the server side of a handshake over `input` and `output`.
pub fn server(input: *Io.Reader, output: *Io.Writer, options: config.Server) HandshakeError!Connection {
    try policy.checkServer(options);
    if (options.auth == null and options.certificates.len == 0 and options.select_certificate == null) return error.TlsInternalError;
    const g = try globals();
    var conn = try Connection.init(g.server_ctx, input, output, .server);
    errdefer conn.deinit();
    const ssl = conn.ssl;
    c.SSL_set_accept_state(ssl);

    // The server speaks TLS 1.3 only, as the native one does.
    try setVersions(ssl, c.TLS1_3_VERSION, c.TLS1_3_VERSION);
    try setCipherSuites(ssl, options.cipher_suites);
    try setPreferences(ssl, options.named_groups, options.signing_schemes, options.verify_schemes);
    // libssl holds every handshake message to this, but to no less than
    // 16 KiB.
    c.SSL_set_max_cert_list(ssl, options.max_handshake_message_len);
    if (options.client_auth) |auth| {
        const mode: c_int = switch (auth.auth_type) {
            .request => c.SSL_VERIFY_PEER,
            .require => c.SSL_VERIFY_PEER | c.SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
        };
        c.SSL_set_custom_verify(ssl, mode, verifyCallback);
    }

    conn.options = .{ .server = &options };
    conn.runHandshake() catch |err| {
        conn.options = .none;
        return err;
    };
    conn.options = .none;
    conn.alpn_protocol = selectedAlpn(ssl, options.alpn_protocols);
    conn.strict_close_notify = options.strict_close_notify;
    if (c.SSL_get_servername(ssl, c.TLSEXT_NAMETYPE_host_name)) |name| conn.setServerName(std.mem.span(name));
    try conn.finishHandshake(options.gpa, options.keep_peer_certificates);
    return conn;
}

fn setVersions(ssl: *c.SSL, min: u16, max: u16) error{TlsInternalError}!void {
    if (c.SSL_set_min_proto_version(ssl, min) != 1) return error.TlsInternalError;
    if (c.SSL_set_max_proto_version(ssl, max) != 1) return error.TlsInternalError;
}

/// Hands libssl the suites in our order: TLS 1.3's by their standard
/// names, TLS 1.2's by OpenSSL's.
fn setCipherSuites(ssl: *c.SSL, suites: []const proto.CipherSuite) error{TlsInternalError}!void {
    var tls13: [512]u8 = undefined;
    var tls12: [1024]u8 = undefined;
    var w13: Io.Writer = .fixed(&tls13);
    var w12: Io.Writer = .fixed(&tls12);
    for (suites) |suite| {
        const libssl_cipher = c.SSL_get_cipher_by_value(@intFromEnum(suite)) orelse return error.TlsInternalError;
        const is_tls13 = suite.version() == .tls_1_3;
        const w = if (is_tls13) &w13 else &w12;
        const name = if (is_tls13) c.SSL_CIPHER_standard_name(libssl_cipher) else c.SSL_CIPHER_get_name(libssl_cipher);
        if (w.end > 0) w.writeByte(':') catch return error.TlsInternalError;
        w.writeAll(std.mem.span(name)) catch return error.TlsInternalError;
    }
    w13.writeByte(0) catch return error.TlsInternalError;
    w12.writeByte(0) catch return error.TlsInternalError;
    if (w13.end > 1 and c.SSL_set_ciphersuites(ssl, &tls13) != 1) return error.TlsInternalError;
    if (w12.end > 1 and c.SSL_set_strict_cipher_list(ssl, &tls12) != 1) return error.TlsInternalError;
}

/// Groups and signature schemes in our order. libssl's own defaults
/// differ: its client offers no Ed25519, for one.
fn setPreferences(
    ssl: *c.SSL,
    groups: []const proto.NamedGroup,
    signing: []const proto.SignatureScheme,
    verify: []const proto.SignatureScheme,
) error{TlsInternalError}!void {
    var nids: [16]c_int = undefined;
    var n: usize = 0;
    for (groups) |group| {
        const nid: c_int = switch (group) {
            .x25519_ml_kem768 => c.NID_X25519MLKEM768,
            .x25519 => c.NID_X25519,
            .secp256r1 => c.NID_X9_62_prime256v1,
            .secp384r1 => c.NID_secp384r1,
            .secp521r1 => c.NID_secp521r1,
            else => continue,
        };
        if (n == nids.len) return error.TlsInternalError;
        nids[n] = nid;
        n += 1;
    }
    if (n == 0 or c.SSL_set1_groups(ssl, &nids, n) != 1) return error.TlsInternalError;
    try setSchemes(ssl, signing, c.SSL_set_signing_algorithm_prefs);
    try setSchemes(ssl, verify, c.SSL_set_verify_algorithm_prefs);
}

fn setSchemes(ssl: *c.SSL, schemes: []const proto.SignatureScheme, set: anytype) error{TlsInternalError}!void {
    var ids: [32]u16 = undefined;
    if (schemes.len > ids.len) return error.TlsInternalError;
    for (schemes, ids[0..schemes.len]) |scheme, *id| id.* = @intFromEnum(scheme);
    if (set(ssl, &ids, schemes.len) != 1) return error.TlsInternalError;
}

fn terminated(buf: []u8, s: []const u8) error{TlsInternalError}![*:0]const u8 {
    if (s.len >= buf.len or std.mem.indexOfScalar(u8, s, 0) != null) return error.TlsInternalError;
    @memcpy(buf[0..s.len], s);
    buf[s.len] = 0;
    return buf[0..s.len :0];
}

/// The client's ALPN offer, in wire form.
fn setAlpn(ssl: *c.SSL, gpa: std.mem.Allocator, protocols: []const []const u8) HandshakeError!void {
    var len: usize = 0;
    for (protocols) |name| {
        if (name.len == 0 or name.len > 255) return error.TlsInternalError;
        len += 1 + name.len;
    }
    if (len > 0xffff) return error.TlsInternalError;
    const wire = try gpa.alloc(u8, len);
    defer gpa.free(wire);
    var i: usize = 0;
    for (protocols) |name| {
        wire[i] = @intCast(name.len);
        @memcpy(wire[i + 1 ..][0..name.len], name);
        i += 1 + name.len;
    }
    // libssl copies it, and returns 0 for success.
    if (c.SSL_set_alpn_protos(ssl, wire.ptr, wire.len) != 0) return error.OutOfMemory;
}

/// The agreed protocol, as the configuration's own slice.
fn selectedAlpn(ssl: *c.SSL, ours: []const []const u8) ?[]const u8 {
    var data: [*c]const u8 = null;
    var len: c_uint = 0;
    c.SSL_get0_alpn_selected(ssl, &data, &len);
    if (len == 0) return null;
    for (ours) |name| {
        if (std.mem.eql(u8, name, data[0..len])) return name;
    }
    return null;
}

/// The longest signature a hook may make, as in the native handshake.
const max_signature_len = 1024;

/// A signature the certificate's hook makes in libssl's stead.
const Signing = struct {
    algorithm: crypto.sig.Algorithm,
    /// What to sign, copied from libssl; `gpa`'s.
    message: []u8,
    signature_buf: [max_signature_len]u8 = undefined,
    /// A slice of `signature_buf`, once the hook has signed.
    signature: ?[]const u8 = null,
};

/// libssl's interface to keys it does not hold: ours, for the signer hook.
const key_method: c.SSL_PRIVATE_KEY_METHOD = .{
    .sign = signCallback,
    .decrypt = null,
    .complete = completeCallback,
};

/// Gives the connection a certificate chain and its key, or its signer.
fn setCertificate(conn: *Connection, pair: *const config.CertKeyPair) HandshakeError!void {
    const ssl = conn.ssl;
    if (pair.signer != null and pair.key.maxSignatureLength() > max_signature_len) return error.TlsInternalError;
    conn.certificate = pair;
    var buffers: [config.CertKeyPair.max_chain_len]*c.CRYPTO_BUFFER = undefined;
    var n: usize = 0;
    defer for (buffers[0..n]) |b| c.CRYPTO_BUFFER_free(b);
    for (pair.chain) |der| {
        buffers[n] = c.CRYPTO_BUFFER_new(der.ptr, der.len, null) orelse return error.OutOfMemory;
        n += 1;
    }
    const ok = if (pair.signer != null)
        c.SSL_set_chain_and_key(ssl, @ptrCast(&buffers), n, null, &key_method)
    else
        c.SSL_set_chain_and_key(ssl, @ptrCast(&buffers), n, pair.key.pkey, null);
    if (ok != 1) {
        c.ERR_clear_error();
        return error.TlsInternalError;
    }
}

/// The peer's certificates as libssl holds them, leaf first.
const PeerChain = struct {
    stack: ?*const c.struct_stack_st_CRYPTO_BUFFER,
    len: usize,

    fn get(chain: PeerChain, i: usize) []const u8 {
        const buffer = c.sk_CRYPTO_BUFFER_value(chain.stack, i).?;
        return c.CRYPTO_BUFFER_data(buffer)[0..c.CRYPTO_BUFFER_len(buffer)];
    }
};

fn peerChain(ssl: *c.SSL) PeerChain {
    const stack = c.SSL_get0_peer_certificates(ssl);
    return .{ .stack = stack, .len = if (stack) |s| c.sk_CRYPTO_BUFFER_num(s) else 0 };
}

// Callbacks. Each runs inside a libssl call, under the connection's mutex,
// and only computes.

fn connectionOf(ssl: ?*const c.SSL) *Connection {
    return @ptrCast(@alignCast(c.SSL_get_ex_data(ssl, globals_value.?.ex_index).?));
}

fn infoCallback(ssl: ?*const c.SSL, kind: c_int, value: c_int) callconv(.c) void {
    const read_alert = kind & c.SSL_CB_READ_ALERT == c.SSL_CB_READ_ALERT;
    const write_alert = kind & c.SSL_CB_WRITE_ALERT == c.SSL_CB_WRITE_ALERT;
    if (!read_alert and !write_alert) return;
    // Only fatal ones end the connection.
    if (value >> 8 != c.SSL3_AL_FATAL) return;
    const conn = connectionOf(ssl);
    const alert: proto.Alert = @enumFromInt(@as(u8, @truncate(@as(c_uint, @bitCast(value)))));
    if (read_alert) conn.alert_received = alert else conn.alert_sent = alert;
}

/// Counts KeyUpdates. libssl reports each whole handshake message it reads
/// or writes, and each record header.
fn messageCallback(write_p: c_int, version: c_int, content_type: c_int, buf: ?*const anyopaque, len: usize, ssl: ?*c.SSL, arg: ?*anyopaque) callconv(.c) void {
    _ = version;
    _ = arg;
    if (content_type != c.SSL3_RT_HANDSHAKE or len != 5) return;
    const bytes: *const [5]u8 = @ptrCast(buf.?);
    // Only a well-formed one, as the native side counts: libssl reports a
    // message it reads before it checks it.
    if (bytes[0] != @intFromEnum(proto.HandshakeType.key_update)) return;
    if (!std.mem.eql(u8, bytes[1..4], &.{ 0, 0, 1 }) or bytes[4] > 1) return;
    const conn = connectionOf(ssl);
    const counter = if (write_p != 0) &conn.key_updates_sent else &conn.key_updates_received;
    _ = counter.fetchAdd(1, .monotonic);
}

/// The server asked for a certificate: ours goes out if our key can sign
/// under one of the schemes the server takes, and none goes out otherwise,
/// as in the native client.
fn clientCertificateCallback(ssl: ?*c.SSL, arg: ?*anyopaque) callconv(.c) c_int {
    _ = arg;
    const conn = connectionOf(ssl);
    const opt = conn.options.client;
    const pair = opt.auth.?;
    var algs: [*c]const u16 = null;
    const len = c.SSL_get0_peer_verify_algorithms(ssl, &algs);
    const theirs: []const proto.SignatureScheme = if (len == 0) &.{} else @ptrCast(algs[0..len]);
    const version: policy.Version = if (c.SSL_version(ssl) == c.TLS1_2_VERSION) .tls12 else .tls13;
    if (policy.selectScheme(opt.signing_schemes, pair.key.key_type, theirs, version) == null) return 1;
    setCertificate(conn, pair) catch |err| {
        conn.callback_error = err;
        return 0;
    };
    return 1;
}

/// libssl wants a signature: take a copy of what to sign and have libssl
/// wait while the hook signs it, outside the libssl call.
fn signCallback(
    ssl: ?*c.SSL,
    out: [*c]u8,
    out_len: [*c]usize,
    max_out: usize,
    signature_algorithm: u16,
    in: [*c]const u8,
    in_len: usize,
) callconv(.c) c.enum_ssl_private_key_result_t {
    _ = .{ out, out_len, max_out };
    const conn = connectionOf(ssl);
    const scheme: proto.SignatureScheme = @enumFromInt(signature_algorithm);
    const version: policy.Version = if (c.SSL_version(ssl) == c.TLS1_2_VERSION) .tls12 else .tls13;
    const algorithm = policy.schemeAlgorithm(scheme, version) orelse {
        conn.callback_error = error.TlsInternalError;
        return c.ssl_private_key_failure;
    };
    const gpa = conn.optionsGpa();
    const job = gpa.create(Signing) catch {
        conn.callback_error = error.OutOfMemory;
        return c.ssl_private_key_failure;
    };
    job.* = .{ .algorithm = algorithm, .message = gpa.dupe(u8, in[0..in_len]) catch {
        gpa.destroy(job);
        conn.callback_error = error.OutOfMemory;
        return c.ssl_private_key_failure;
    } };
    conn.signing = job;
    return c.ssl_private_key_retry;
}

/// libssl collects the signature the hook made.
fn completeCallback(ssl: ?*c.SSL, out: [*c]u8, out_len: [*c]usize, max_out: usize) callconv(.c) c.enum_ssl_private_key_result_t {
    const conn = connectionOf(ssl);
    const job = conn.signing orelse return c.ssl_private_key_failure;
    const signature = job.signature orelse {
        // The hook failed, as the native handshake reports it.
        conn.callback_error = error.TlsInternalError;
        return c.ssl_private_key_failure;
    };
    if (signature.len > max_out) {
        conn.callback_error = error.TlsInternalError;
        return c.ssl_private_key_failure;
    }
    @memcpy(out[0..signature.len], signature);
    out_len.* = signature.len;
    return c.ssl_private_key_success;
}

/// Checks the peer's chain as the native implementation does.
fn verifyCallback(ssl: ?*c.SSL, out_alert: [*c]u8) callconv(.c) c.enum_ssl_verify_result_t {
    const conn = connectionOf(ssl);
    verifyPeer(conn) catch |err| {
        conn.callback_error = err;
        out_alert.* = @intFromEnum(proto.Alert.forLocalError(err) orelse .internal_error);
        return c.ssl_verify_invalid;
    };
    return c.ssl_verify_ok;
}

fn verifyPeer(conn: *Connection) HandshakeError!void {
    const chain = peerChain(conn.ssl);
    if (chain.len == 0) return error.TlsBadCertificate;
    if (chain.len > config.CertKeyPair.max_chain_len) return error.TlsBadCertificate;
    var certs: [config.CertKeyPair.max_chain_len]x509.Certificate = undefined;
    var n: usize = 0;
    defer for (certs[0..n]) |*cert| cert.deinit();
    for (0..chain.len) |i| {
        certs[n] = x509.Certificate.parseDer(chain.get(i)) catch return error.TlsBadCertificate;
        n += 1;
    }
    var key = certs[0].publicKey() catch return error.TlsUnsupportedCertificate;
    key.deinit();
    switch (conn.options) {
        .none => unreachable,
        .client => |opt| try policy.verifyChain(certs[0..n], opt.root_ca.?, .server, opt.host, opt.now.toSeconds()),
        .server => |opt| try policy.verifyChain(certs[0..n], opt.client_auth.?.root_ca, .client, null, opt.now.toSeconds()),
    }
}

/// The server's ALPN choice: our most preferred protocol the client
/// offered. An offer we share nothing with is refused (RFC 7301 §3.2).
fn alpnSelectCallback(
    ssl: ?*c.SSL,
    out: [*c][*c]const u8,
    out_len: [*c]u8,
    in: [*c]const u8,
    in_len: c_uint,
    arg: ?*anyopaque,
) callconv(.c) c_int {
    _ = arg;
    const conn = connectionOf(ssl);
    const ours = conn.options.server.alpn_protocols;
    if (ours.len == 0) return c.SSL_TLSEXT_ERR_NOACK;
    const offered = in[0..in_len];
    for (ours) |name| {
        var i: usize = 0;
        while (i < offered.len) {
            const len = offered[i];
            if (len == 0 or i + 1 + len > offered.len) {
                conn.callback_error = error.TlsIllegalParameter;
                return c.SSL_TLSEXT_ERR_ALERT_FATAL;
            }
            const candidate = offered[i + 1 ..][0..len];
            if (std.mem.eql(u8, candidate, name)) {
                out.* = name.ptr;
                out_len.* = @intCast(name.len);
                return c.SSL_TLSEXT_ERR_OK;
            }
            i += 1 + len;
        }
    }
    conn.callback_error = error.TlsNoApplicationProtocol;
    return c.SSL_TLSEXT_ERR_ALERT_FATAL;
}

/// The server's certificate, picked as the native server picks it: the
/// application's choice, else the first of `certificates` for the client's
/// server name that it can verify, else `auth`.
fn selectCertificateCallback(hello: [*c]const c.SSL_CLIENT_HELLO) callconv(.c) c.enum_ssl_select_cert_result_t {
    const ssl = hello.*.ssl.?;
    const conn = connectionOf(ssl);
    const pair = selectCertificate(hello, ssl, conn.options.server.*) catch |err| {
        conn.selection_error = err;
        return c.ssl_select_cert_success;
    };
    setCertificate(conn, pair) catch |err| {
        conn.selection_error = err;
        return c.ssl_select_cert_success;
    };
    return c.ssl_select_cert_success;
}

/// Fails the handshake for a certificate selection that failed, with the
/// native server's alert. Otherwise acknowledges no server name, as the
/// native server does not.
fn serverNameCallback(ssl: ?*c.SSL, alert: ?*c_int, arg: ?*anyopaque) callconv(.c) c_int {
    _ = arg;
    const conn = connectionOf(ssl.?);
    const err = conn.selection_error orelse return c.SSL_TLSEXT_ERR_NOACK;
    conn.selection_error = null;
    conn.callback_error = err;
    const native = proto.Alert.forLocalError(err) orelse .internal_error;
    alert.?.* = @intFromEnum(native);
    return c.SSL_TLSEXT_ERR_ALERT_FATAL;
}

const max_schemes = 64;

fn selectCertificate(hello: [*c]const c.SSL_CLIENT_HELLO, ssl: *c.SSL, opt: config.Server) HandshakeError!*const config.CertKeyPair {
    var schemes_buf: [max_schemes]proto.SignatureScheme = undefined;
    const schemes = offeredSchemes(hello, &schemes_buf);
    const server_name: ?[]const u8 = if (c.SSL_get_servername(ssl, c.TLSEXT_NAMETYPE_host_name)) |name| std.mem.span(name) else null;
    if (opt.select_certificate) |select| {
        const info: config.SelectCertificate.Hello = .{
            .server_name = server_name,
            .accepts = acceptsKey,
            .schemes = schemes,
            .signing_schemes = opt.signing_schemes,
        };
        if (select.callback(select.context, info)) |pair| return pair;
    }
    for (opt.certificates) |pair| {
        if (policy.selectScheme(opt.signing_schemes, pair.key.key_type, schemes, .tls13) == null) continue;
        if (server_name) |name| {
            if (!pair.leaf.matchesHost(name)) continue;
        }
        return pair;
    }
    return opt.auth orelse error.TlsUnrecognizedName;
}

fn acceptsKey(hello: *const config.SelectCertificate.Hello, key_type: crypto.sig.KeyType) bool {
    return policy.selectScheme(hello.signing_schemes, key_type, hello.schemes, .tls13) != null;
}

/// The client's signature_algorithms that ztls supports, in its order.
fn offeredSchemes(hello: [*c]const c.SSL_CLIENT_HELLO, buf: *[max_schemes]proto.SignatureScheme) []const proto.SignatureScheme {
    var data: [*c]const u8 = null;
    var len: usize = 0;
    if (c.SSL_early_callback_ctx_extension_get(hello, c.TLSEXT_TYPE_signature_algorithms, &data, &len) != 1) return buf[0..0];
    const ext = data[0..len];
    if (ext.len < 2) return buf[0..0];
    const list_len = std.mem.readInt(u16, ext[0..2], .big);
    const list = ext[2..][0..@min(list_len, ext.len - 2)];
    var n: usize = 0;
    var i: usize = 0;
    while (i + 2 <= list.len and n < buf.len) : (i += 2) {
        const scheme: proto.SignatureScheme = @enumFromInt(std.mem.readInt(u16, list[i..][0..2], .big));
        if (policy.schemeAlgorithm(scheme, .tls13) == null) continue;
        buf[n] = scheme;
        n += 1;
    }
    return buf[0..n];
}

// Process-wide state, made on first use.

const Globals = struct {
    client_ctx: *c.SSL_CTX,
    server_ctx: *c.SSL_CTX,
    ex_index: c_int,
};

var globals_mutex: Io.Mutex = .init;
var globals_value: ?Globals = null;

fn globals() error{OutOfMemory}!Globals {
    lock(&globals_mutex);
    defer unlock(&globals_mutex);
    if (globals_value) |g| return g;
    defer c.ERR_clear_error();

    const client_ctx = try newCtx();
    errdefer c.SSL_CTX_free(client_ctx);
    const server_ctx = try newCtx();
    errdefer c.SSL_CTX_free(server_ctx);
    // No resumption yet, as in the native implementation: no tickets.
    if (c.SSL_CTX_set_num_tickets(server_ctx, 0) != 1) return error.OutOfMemory;
    c.SSL_CTX_set_alpn_select_cb(server_ctx, alpnSelectCallback, null);
    c.SSL_CTX_set_select_certificate_cb(server_ctx, selectCertificateCallback);
    if (c.SSL_CTX_set_tlsext_servername_callback(server_ctx, serverNameCallback) != 1) return error.OutOfMemory;

    const index = c.SSL_get_ex_new_index(0, null, null, null, null);
    if (index < 0) return error.OutOfMemory;
    globals_value = .{ .client_ctx = client_ctx, .server_ctx = server_ctx, .ex_index = index };
    return globals_value.?;
}

fn newCtx() error{OutOfMemory}!*c.SSL_CTX {
    const ctx = c.SSL_CTX_new(c.TLS_method()) orelse return error.OutOfMemory;
    _ = c.SSL_CTX_set_session_cache_mode(ctx, c.SSL_SESS_CACHE_OFF);
    return ctx;
}

// Helpers

/// `std.Io.Threaded`'s mutex, which blocks the thread, not the fiber: what
/// it guards never waits, so a holder never yields and the wait is short.
/// Zig 0.17 made the plain lock cancelable.
fn lock(m: *Io.Mutex) void {
    if (@hasDecl(Io.Threaded, "mutexLockUncancelable")) {
        Io.Threaded.mutexLockUncancelable(m);
    } else {
        Io.Threaded.mutexLock(m);
    }
}

fn unlock(m: *Io.Mutex) void {
    Io.Threaded.mutexUnlock(m);
}

/// A failure of the handshake as one of a connection's, for those that can
/// only come after it.
fn asFailure(err: HandshakeError) Failure {
    inline for (comptime errorNames(Failure)) |name| {
        if (err == @field(HandshakeError, name)) return @field(Failure, name);
    }
    return error.TlsInternalError;
}

/// The names in an error set; Zig 0.16 and 0.17 describe sets differently.
fn errorNames(comptime E: type) []const [:0]const u8 {
    comptime {
        const set = @typeInfo(E).error_set;
        if (@typeInfo(@TypeOf(set)) == .optional) {
            var names: [set.?.len][:0]const u8 = undefined;
            for (set.?, 0..) |e, i| names[i] = e.name;
            const final = names;
            return &final;
        }
        return set.error_names.?;
    }
}

/// The failure an alert we sent stands for.
fn localError(alert: proto.Alert) HandshakeError {
    return switch (alert) {
        .unexpected_message => error.TlsUnexpectedMessage,
        .bad_record_mac => error.TlsBadRecordMac,
        .record_overflow => error.TlsRecordOverflow,
        .handshake_failure => error.TlsHandshakeFailure,
        .bad_certificate => error.TlsBadCertificate,
        .unsupported_certificate => error.TlsUnsupportedCertificate,
        .certificate_revoked => error.TlsCertificateRevoked,
        .certificate_expired => error.CertificateExpired,
        .certificate_unknown => error.TlsCertificateUnknown,
        .illegal_parameter => error.TlsIllegalParameter,
        .unknown_ca => error.CertificateIssuerNotFound,
        .access_denied => error.TlsAccessDenied,
        .decode_error => error.TlsDecodeError,
        .decrypt_error => error.TlsDecryptError,
        .protocol_version => error.TlsProtocolVersion,
        .insufficient_security => error.TlsInsufficientSecurity,
        .inappropriate_fallback => error.TlsInappropriateFallback,
        .no_renegotiation => error.TlsNoRenegotiation,
        .missing_extension => error.TlsMissingExtension,
        .unsupported_extension => error.TlsUnsupportedExtension,
        .unrecognized_name => error.TlsUnrecognizedName,
        .bad_certificate_status_response => error.TlsBadCertificateStatusResponse,
        .unknown_psk_identity => error.TlsUnknownPskIdentity,
        .certificate_required => error.TlsCertificateRequired,
        .no_application_protocol => error.TlsNoApplicationProtocol,
        else => error.TlsInternalError,
    };
}

/// Where the ciphertext libssl took ends: inside a record, or between two.
/// libssl reads a record's header, then exactly its body.
const RecordTracker = struct {
    header: [5]u8 = undefined,
    header_len: u8 = 0,
    body_left: u16 = 0,

    fn feed(t: *RecordTracker, bytes: []const u8) void {
        var rest = bytes;
        while (rest.len > 0) {
            if (t.body_left > 0) {
                const n: u16 = @intCast(@min(rest.len, t.body_left));
                t.body_left -= n;
                rest = rest[n..];
                continue;
            }
            const n = @min(rest.len, t.header.len - t.header_len);
            @memcpy(t.header[t.header_len..][0..n], rest[0..n]);
            t.header_len += @intCast(n);
            rest = rest[n..];
            if (t.header_len == t.header.len) {
                t.header_len = 0;
                t.body_left = std.mem.readInt(u16, t.header[3..5], .big);
            }
        }
    }

    fn atBoundary(t: *const RecordTracker) bool {
        return t.header_len == 0 and t.body_left == 0;
    }
};
