//! A TLS connection on the system's OpenSSL (`-Dimpl=openssl`), with the
//! native `Connection`'s API: `client` and `server` run the handshake over
//! the transport's reader and writer, and the connection hands out a
//! cleartext reader and writer.
//!
//! This is the libssl engine (`src/libssl/connection.zig`) moved to
//! OpenSSL's API, and works the same way. What OpenSSL has no hook for is
//! refused when the handshake starts: a certificate's `signer`, and the
//! server's `select_certificate`. The options are the policy, as in the
//! other engines: OpenSSL's security level is 0, so that it refuses
//! nothing they allow, such as a client's explicit fallback to TLS 1.0.
//! "libssl" below is OpenSSL's.
//!
//! libssl never waits on the transport. Its BIO, `transport_bio`, only
//! moves bytes the transport's buffers already hold: it reads ciphertext
//! straight from the transport reader's buffer, and says "retry" when that
//! is empty; it writes ciphertext straight into the transport writer's
//! free space, and what does not fit there goes to `spill`, a memory BIO.
//! Transport I/O happens only between libssl calls, in Zig, so a fiber may
//! wait on it and move to another thread: the reading task fills the
//! transport reader, and the writing task flushes the transport writer and
//! moves what is in `spill` to it.
//!
//! What keeps this safe:
//!
//! - A transport failure never reaches libssl. The BIO takes all it is
//!   given, so libssl's writes always finish within the call: it never
//!   stops halfway through a record and never needs a call repeated.
//!   Plaintext counts as written once libssl has taken it; a failed
//!   transport write leaves the ciphertext in `spill` or in the
//!   transport's buffer, for the next flush. The writing task empties
//!   `spill` and makes room for a record before each write, so `spill`
//!   rarely holds anything.
//! - Each transport buffer is touched by the task that owns it only. The
//!   BIO reads the transport reader in the handshake's and the reading
//!   task's calls, and writes to the transport writer in the handshake's
//!   and the writing task's; everything else libssl writes, an alert from
//!   the read side say, goes to `spill`.
//! - Each libssl call's result becomes a `Result`, and every place that
//!   makes a call switches over all of it, with no catch-all.
//! - One libssl object serves both directions, so the reading and the
//!   writing task take turns at it under `mutex`, an `Io.Mutex`: a task
//!   that waits for it parks, and leaves its thread to others. Nothing
//!   under the mutex waits: it covers one libssl call, which only
//!   computes, and our callbacks, which only compute too. Taking it is the
//!   only point where a task may be canceled, before anything was done.
//!   OpenSSL's error queue is thread-local, so it is read and cleared under
//!   the mutex as well, before the fiber can move.
//!
//! As in the native implementation, the read side never writes to the
//! transport. What libssl writes while it reads, a KeyUpdate reply or the
//! alert for a failure, waits in `spill` for the write side, which in the
//! second case then fails with the same error.

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
const max_plaintext_len = api.max_plaintext_len;
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
    /// The peer's close_notify came.
    closed,
    /// The connection is over, for this reason.
    failed: HandshakeError,
};

const WriteState = enum {
    open,
    /// close_notify is in `spill` or the transport's buffer, maybe not yet
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
    /// libssl's BIO for both directions, owned by `ssl`; see the top of the
    /// file.
    transport_bio: *c.BIO,
    /// What libssl wrote that could not go into the transport writer's
    /// buffer, waiting for the writing task: a memory BIO, ours.
    spill: *c.BIO,

    /// Serializes the libssl and BIO calls of the reading and the writing
    /// task and guards what they share, below. Held for one call at a
    /// time, never across transport I/O.
    mutex: Io.Mutex = .init,
    /// What `mutex` waits with: the options' `io`.
    io: Io,
    /// What the BIO may touch in the current call: the transport reader,
    /// and the transport writer.
    may_read: bool = false,
    may_write: bool = false,
    /// The read side's failure: the write side sends its alert, then fails
    /// with it too.
    read_failure: ?Failure = null,
    /// A fatal alert libssl sent or received in the current call.
    alert_sent: ?proto.Alert = null,
    alert_received: ?proto.Alert = null,
    /// A failure one of our callbacks decided in the current call, which
    /// says more than the alert that goes out for it.
    callback_error: ?HandshakeError = null,
    /// What the suites before TLS 1.3 that both the client and we offer
    /// authenticate with, for picking the server's certificate.
    legacy_auth: LegacyAuth = .{},
    /// ClientHellos sent or received, counted by libssl's message
    /// callback: a second one followed a HelloRetryRequest.
    client_hellos: u8 = 0,
    /// KeyUpdates sent and received, counted by libssl's message callback.
    /// Atomic so either task may read them while the other's call runs.
    key_updates_sent: std.atomic.Value(u64) = .init(0),
    key_updates_received: std.atomic.Value(u64) = .init(0),
    options: Options = .none,

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

    fn init(g: Globals, io: Io, input: *Io.Reader, output: *Io.Writer, side: proto.Side) error{OutOfMemory}!Connection {
        if (input.buffer.len < input_buffer_len) @panic("ztls: the transport reader's buffer is shorter than input_buffer_len");
        if (output.buffer.len < output_buffer_len) @panic("ztls: the transport writer's buffer is shorter than output_buffer_len");
        const spill = c.BIO_new(c.BIO_s_mem()) orelse return error.OutOfMemory;
        errdefer _ = c.BIO_free(spill);
        const ssl = c.SSL_new(switch (side) {
            .client => g.client_ctx,
            .server => g.server_ctx,
        }) orelse return error.OutOfMemory;
        errdefer c.SSL_free(ssl);
        // The first set of the index allocates; later ones, in `bind`,
        // only overwrite it.
        if (c.SSL_set_ex_data(ssl, g.ex_index, null) != 1) return error.OutOfMemory;
        const bio = c.BIO_new(g.bio_method) orelse return error.OutOfMemory;
        c.BIO_set_init(bio, 1);
        // The SSL takes it for both directions, and frees it with itself.
        c.SSL_set_bio(ssl, bio, bio);
        c.SSL_set_info_callback(ssl, infoCallback);
        c.SSL_set_msg_callback(ssl, messageCallback);
        return .{ .input = input, .output = output, .ssl = ssl, .transport_bio = bio, .spill = spill, .io = io, .side = side };
    }

    /// Frees libssl's state. Sends nothing; both tasks must be done.
    pub fn deinit(conn: *Connection) void {
        c.SSL_free(conn.ssl);
        _ = c.BIO_free(conn.spill);
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

    /// Waits for the other task's turn at libssl to end. Canceled, it
    /// returns before anything was done.
    fn lock(conn: *Connection) Io.Cancelable!void {
        try conn.mutex.lock(conn.io);
    }

    fn unlock(conn: *Connection) void {
        conn.mutex.unlock(conn.io);
    }

    // libssl calls, all with `mutex` held

    /// Runs one libssl operation. `buf` is the cleartext to read into or
    /// write.
    fn call(conn: *Connection, op: Op, buf: []const u8) Result {
        conn.callback_error = null;
        conn.alert_sent = null;
        conn.alert_received = null;
        conn.bind();
        // Only the task that owns a transport buffer touches it.
        conn.may_read = op == .handshake or op == .read;
        conn.may_write = op != .read;
        defer {
            conn.may_read = false;
            conn.may_write = false;
        }
        const ssl = conn.ssl;
        // libssl has nothing to send for an empty write: what a read owes
        // the peer, it wrote then.
        if (op == .write and buf.len == 0) return .{ .ok = 0 };
        const len: c_int = @intCast(buf.len);
        // Errors are read from the queue below: none may be left from
        // before, which OpenSSL does not clear on entry as AWS-LC does.
        c.ERR_clear_error();
        const rc: c_int = switch (op) {
            .handshake => c.SSL_do_handshake(ssl),
            .read => c.SSL_read(ssl, @constCast(buf.ptr), len),
            .write => c.SSL_write(ssl, buf.ptr, len),
            .shutdown => c.SSL_shutdown(ssl),
            .key_update => keyUpdate(ssl),
        };
        const ok = switch (op) {
            .handshake, .read, .write, .key_update => rc > 0,
            // 0 once close_notify is out, 1 once the peer's came too.
            .shutdown => rc >= 0,
        };
        const result: Result = if (ok) .{ .ok = if (op == .key_update) 0 else @intCast(rc) } else switch (c.SSL_get_error(ssl, rc)) {
            c.SSL_ERROR_WANT_READ => .want_read,
            // Our BIO never refuses a write.
            c.SSL_ERROR_WANT_WRITE => .{ .failed = error.TlsInternalError },
            c.SSL_ERROR_ZERO_RETURN => .closed,
            // Anything else ends the connection, SSL_ERROR_SYSCALL
            // included, which our BIO gives libssl a reason for only when
            // `spill` runs out of memory.
            else => .{ .failed = conn.classify() },
        };
        // Empty the queue for others on this thread.
        c.ERR_clear_error();
        return result;
    }

    /// Points the callbacks and the BIO at this connection, which may have
    /// moved since the last call.
    fn bind(conn: *Connection) void {
        // Cannot fail: `init` made the slot.
        _ = c.SSL_set_ex_data(conn.ssl, globals_value.?.ex_index, conn);
        c.BIO_set_data(conn.transport_bio, conn);
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
        if (conn.alert_sent) |alert| return alert.localError();
        return error.TlsInternalError;
    }

    // Moving ciphertext to the transport: the handshake's task or the
    // writing task only.

    /// Moves what libssl wrote from `spill` into the transport writer,
    /// flushing that whenever it fills, and at the end too when `flush` is
    /// set. A transport failure or a cancellation leaves what was not sent
    /// where it is, for the next time.
    fn sendWritten(conn: *Connection, flush: bool) error{ WriteFailed, Canceled }!void {
        while (true) {
            try conn.lock();
            const space = conn.output.unusedCapacitySlice();
            const want = @min(c.BIO_ctrl_pending(conn.spill), space.len, std.math.maxInt(c_int));
            const got = if (want == 0) 0 else c.BIO_read(conn.spill, space.ptr, @intCast(want));
            const left = c.BIO_ctrl_pending(conn.spill);
            conn.unlock();
            // A memory BIO hands over what it holds.
            if (got != @as(c_int, @intCast(want))) @panic("ztls: a memory BIO failed to hand over its contents");
            conn.output.advance(want);
            if (left == 0) break;
            conn.output.flush() catch return error.WriteFailed;
        }
        if (flush) conn.output.flush() catch return error.WriteFailed;
    }

    /// Whether `spill` holds something not yet moved to the transport.
    fn writtenPending(conn: *Connection) bool {
        return c.BIO_ctrl_pending(conn.spill) > 0;
    }

    // Handshake

    /// Runs the handshake to its end, with both of the transport's sides,
    /// with `options` there for the callbacks.
    fn runHandshake(conn: *Connection, options: Options) HandshakeError!void {
        conn.options = options;
        defer conn.options = .none;
        while (true) {
            try conn.lock();
            // OpenSSL has no call to send an alert of our choosing, as
            // AWS-LC has: on a failure the peer hears what libssl sent,
            // which our callbacks steer where they can.
            const step = conn.call(.handshake, "");
            conn.unlock();
            switch (step) {
                .ok => return conn.sendWritten(true),
                .want_read => {
                    try conn.sendWritten(true);
                    try conn.input.fillMore();
                },
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

    /// Records what the handshake settled.
    fn finishHandshake(conn: *Connection, gpa: std.mem.Allocator, keep_peer_certificates: bool) error{OutOfMemory}!void {
        const ssl = conn.ssl;
        conn.version = @enumFromInt(c.SSL_version(ssl));
        if (c.SSL_get_current_cipher(ssl)) |current| conn.suite = @enumFromInt(c.SSL_CIPHER_get_protocol_id(current));
        conn.group = negotiatedGroup(ssl);
        conn.retried = conn.client_hellos > 1;
        conn.peer_signature_scheme = peerSignatureScheme(ssl);

        const chain = peerChain(ssl, conn.side);
        if (chain.len > 0) conn.peer_key_type = leafKeyType(chain.get(0));
        if (keep_peer_certificates and chain.len > 0) {
            var copies: std.ArrayList([]const u8) = .empty;
            errdefer {
                for (copies.items) |der| gpa.free(der);
                copies.deinit(gpa);
            }
            try copies.ensureTotalCapacity(gpa, chain.len);
            for (0..chain.len) |i| copies.appendAssumeCapacity(try derOf(gpa, chain.get(i)));
            conn.peer_certificates = try copies.toOwnedSlice(gpa);
            conn.gpa = gpa;
        }
    }

    // Read side

    /// Ends the read side with `err` for both tasks: the write side sends
    /// the alert libssl wrote, if any, and fails with `err` too. With
    /// `mutex` held.
    fn failRead(conn: *Connection, err: Failure) void {
        conn.read_state = .failed;
        conn.read_failure = err;
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
            try conn.lock();
            const step = conn.call(.read, dest[0..len]);
            const failure: ?Failure = switch (step) {
                .ok, .want_read, .closed => null,
                .failed => |err| asFailure(err),
            };
            if (failure) |err| conn.failRead(err);
            conn.unlock();

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
                        // the transport reader held, so the tracker has
                        // seen what it read.
                        // Between records it is the end, unless the peer
                        // must say so with close_notify.
                        if (conn.tracker.atBoundary() and !conn.strict_close_notify) {
                            conn.read_state = .closed;
                            return error.EndOfStream;
                        }
                        try conn.lock();
                        conn.failRead(error.TlsConnectionTruncated);
                        conn.unlock();
                        return error.TlsConnectionTruncated;
                    },
                },
                // The read side failed, as recorded above.
                .failed => return failure orelse error.TlsInternalError,
            }
        }
    }

    pub const Reader = struct {
        conn: *Connection,
        interface: Io.Reader,
        /// Why the last read failed: a `Failure` of the connection,
        /// `ReadFailed` when the transport reader failed and its own error
        /// says how, or `Canceled` when the task was canceled while it
        /// waited for the writing task's turn at libssl. Those two do not
        /// end the connection, and the read may be retried.
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
    /// runs with `spill` empty and room in the transport writer for what
    /// it seals, so that goes straight there; making room may fail on the
    /// transport, and then nothing was done.
    fn writeOp(conn: *Connection, op: Op, bytes: []const u8) WriteError!void {
        if (bytes.len > max_plaintext_len) @panic("ztls: more than a record's worth given to one write");
        // The sealed record, and a KeyUpdate reply that may go ahead of it:
        // `output_buffer_len` holds both, with room to spare.
        const room = bytes.len + (output_buffer_len - max_plaintext_len);
        while (true) {
            try conn.lock();
            if (conn.read_failure) |err| {
                conn.unlock();
                return conn.takeReadFailure(err);
            }
            if (conn.writtenPending()) {
                conn.unlock();
                try conn.sendWritten(false);
                continue;
            }
            // Only this task writes to the transport, so the room stays.
            if (conn.output.end > 0 and conn.output.unusedCapacitySlice().len < room) {
                conn.unlock();
                conn.output.flush() catch return error.WriteFailed;
                continue;
            }
            const step = conn.call(op, bytes);
            conn.unlock();
            switch (step) {
                .ok => return,
                // Neither can happen: none of these reads. libssl may hold
                // half a write now, so the direction is over.
                .want_read, .closed => return conn.failWrite(error.TlsInternalError),
                .failed => |err| {
                    conn.sendWritten(true) catch {};
                    return conn.failWrite(asFailure(err));
                },
            }
        }
    }

    /// Encrypts `bytes`, at most a record's worth, into the transport
    /// writer.
    fn writeRecord(conn: *Connection, bytes: []const u8) WriteError!void {
        try conn.checkWritable();
        try conn.writeOp(.write, bytes);
    }

    /// Sends everything encrypted, and what libssl wrote while it read: a
    /// KeyUpdate reply, say.
    fn flushWrite(conn: *Connection) WriteError!void {
        try conn.checkWritable();
        try conn.writeOp(.write, "");
        try conn.sendWritten(true);
    }

    /// Asks the peer to update its keys, updating ours, and sends the
    /// request. Does nothing before TLS 1.3, which has no KeyUpdate. After a
    /// transport failure the update may have happened with only the flush
    /// left; calling this again makes another update.
    fn requestKeyUpdate(conn: *Connection) WriteError!void {
        try conn.checkWritable();
        if (conn.version != .tls_1_3) return;
        try conn.writeOp(.key_update, "");
        try conn.sendWritten(true);
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
        try conn.sendWritten(true);
        conn.write_state = .closed;
    }

    pub const Writer = struct {
        conn: *Connection,
        interface: Io.Writer,
        /// Why the last write failed: a `Failure` of the connection, the
        /// read side's included since its alert goes out this way,
        /// `WriteFailed` when the transport writer failed and its own
        /// error says how, or `Canceled` when the task was canceled while
        /// it waited for the reading task's turn at libssl. Those two do
        /// not end the connection: what was encrypted waits for the next
        /// flush, and what was not is still in this writer, or was not
        /// taken from the caller.
        err: ?WriteError = null,

        fn fail(self: *Writer, err: WriteError) Io.Writer.Error {
            self.err = err;
            return error.WriteFailed;
        }

        /// Encrypts what is buffered, a record at a time, or when nothing
        /// is, one record from the start of `data`. Takes from the buffer
        /// and from `data` only what libssl took.
        fn drain(w: *Io.Writer, data: []const []const u8, splat: usize) Io.Writer.Error!usize {
            const self: *Writer = @fieldParentPtr("interface", w);
            const conn = self.conn;
            if (w.end > 0) {
                var done: usize = 0;
                defer _ = w.consume(done);
                while (done < w.end) {
                    const n = @min(w.end - done, max_plaintext_len);
                    conn.writeRecord(w.buffer[done..][0..n]) catch |err| return self.fail(err);
                    done += n;
                }
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
            _ = try drain(w, &.{""}, 1);
            self.conn.flushWrite() catch |err| return self.fail(err);
        }

        /// Sends what is buffered, then asks the peer to update its keys,
        /// updating ours first. Does nothing before TLS 1.3.
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

/// A KeyUpdate request, sent at once: libssl sends a requested update
/// with the next handshake step or write. A reply a read owed is out
/// already.
fn keyUpdate(ssl: *c.SSL) c_int {
    if (c.SSL_key_update(ssl, c.SSL_KEY_UPDATE_REQUESTED) != 1) return -1;
    return c.SSL_do_handshake(ssl);
}

/// What libssl found wrong in a record, for the failures it may have sent
/// no alert for, as after our close_notify.
fn reasonError(packed_error: err_code) ?HandshakeError {
    // System errors carry an errno, not a library and reason.
    if (packed_error & c.ERR_SYSTEM_FLAG != 0) return null;
    if ((packed_error >> c.ERR_LIB_OFFSET) & c.ERR_LIB_MASK != c.ERR_LIB_SSL) return null;
    return switch (packed_error & c.ERR_REASON_MASK) {
        c.SSL_R_DECRYPTION_FAILED_OR_BAD_RECORD_MAC => error.TlsBadRecordMac,
        c.SSL_R_ENCRYPTED_LENGTH_TOO_LONG, c.SSL_R_DATA_LENGTH_TOO_LONG, c.SSL_R_PACKET_LENGTH_TOO_LONG => error.TlsRecordOverflow,
        c.SSL_R_UNEXPECTED_RECORD, c.SSL_R_UNEXPECTED_MESSAGE => error.TlsUnexpectedMessage,
        c.SSL_R_NO_RENEGOTIATION => error.TlsNoRenegotiation,
        c.SSL_R_EXCESSIVE_MESSAGE_SIZE => error.TlsIllegalParameter,
        else => null,
    };
}

const err_code = crypto.err.Code;

// Setup

/// Runs the client side of a handshake over `input` and `output`.
pub fn client(input: *Io.Reader, output: *Io.Writer, options: config.Client) HandshakeError!Connection {
    try policy.checkClient(options);
    // OpenSSL has no hook for a key held elsewhere.
    if (options.auth) |pair| {
        if (pair.signer != null) return error.TlsInternalError;
    }
    // A failed setup call leaves its error on this thread's queue.
    errdefer c.ERR_clear_error();
    const g = try globals(options.io);
    var conn = try Connection.init(g, options.io, input, output, .client);
    errdefer conn.deinit();
    const ssl = conn.ssl;
    c.SSL_set_connect_state(ssl);

    if (options.cipher_suites) |suites| {
        const ours = policy.offeredSuites(suites, crypto.aead.hasAesHardware());
        try setVersions(ssl, options.min_version, options.max_version, ours);
        try setCipherSuites(ssl, ours);
    } else {
        try setVersions(ssl, options.min_version, options.max_version, null);
    }
    try setGroups(ssl, options.named_groups, options.key_shares);
    // What the server may sign with, and what our certificate may.
    try setSchemes(ssl, c.SSL_CTRL_SET_SIGALGS_LIST, options.verify_schemes orelse openssl_schemes);
    try setSchemes(ssl, c.SSL_CTRL_SET_CLIENT_SIGALGS_LIST, options.signing_schemes orelse openssl_schemes);
    // libssl holds a Certificate message to this, but to no less than
    // 16 KiB.
    _ = c.SSL_ctrl(ssl, c.SSL_CTRL_SET_MAX_CERT_LIST, @intCast(options.max_handshake_message_len), null);

    var name_buf: [256]u8 = undefined;
    if (policy.sendsSni(options.host)) {
        const name = try terminated(&name_buf, options.host);
        if (c.SSL_ctrl(ssl, c.SSL_CTRL_SET_TLSEXT_HOSTNAME, c.TLSEXT_NAMETYPE_host_name, @constCast(name)) != 1) return error.TlsInternalError;
        conn.setServerName(options.host);
    }
    // The chain is checked in `verifyCallback`, which passes it when
    // verification is off.
    c.SSL_set_verify(ssl, if (options.insecure_skip_verify) c.SSL_VERIFY_NONE else c.SSL_VERIFY_PEER, null);
    if (options.alpn_protocols.len > 0) try setAlpn(ssl, options.gpa, options.alpn_protocols);
    // The certificate is picked when the server asks for one.
    if (options.auth != null) c.SSL_set_cert_cb(ssl, clientCertificateCallback, null);

    try conn.runHandshake(.{ .client = &options });
    conn.alpn_protocol = selectedAlpn(ssl, options.alpn_protocols);
    conn.strict_close_notify = options.strict_close_notify;
    try conn.finishHandshake(options.gpa, options.keep_peer_certificates);
    return conn;
}

/// Runs the server side of a handshake over `input` and `output`.
pub fn server(input: *Io.Reader, output: *Io.Writer, options: config.Server) HandshakeError!Connection {
    try policy.checkServer(options);
    // OpenSSL has no hook for a key held elsewhere, and none that picks a
    // certificate as `select_certificate` does.
    if (options.select_certificate != null) return error.TlsInternalError;
    if (options.auth) |pair| {
        if (pair.signer != null) return error.TlsInternalError;
    }
    for (options.certificates) |pair| {
        if (pair.signer != null) return error.TlsInternalError;
    }
    // A failed setup call leaves its error on this thread's queue.
    errdefer c.ERR_clear_error();
    const g = try globals(options.io);
    var conn = try Connection.init(g, options.io, input, output, .server);
    errdefer conn.deinit();
    const ssl = conn.ssl;
    c.SSL_set_accept_state(ssl);
    // Our order of groups over the client's; the suite is chosen in
    // `clientHelloCallback`.
    _ = c.SSL_set_options(ssl, ssl_op.cipher_server_preference);

    try setVersions(ssl, options.min_version, options.max_version, options.cipher_suites);
    if (options.cipher_suites) |suites| try setCipherSuites(ssl, suites);
    try setGroups(ssl, options.named_groups, &.{});
    // What we sign with, and what a client certificate may sign with.
    try setSchemes(ssl, c.SSL_CTRL_SET_SIGALGS_LIST, options.signing_schemes orelse openssl_schemes);
    try setSchemes(ssl, c.SSL_CTRL_SET_CLIENT_SIGALGS_LIST, options.verify_schemes orelse openssl_schemes);
    // libssl holds a Certificate message to this, but to no less than
    // 16 KiB.
    _ = c.SSL_ctrl(ssl, c.SSL_CTRL_SET_MAX_CERT_LIST, @intCast(options.max_handshake_message_len), null);
    if (options.client_auth) |auth| {
        const mode: c_int = switch (auth.auth_type) {
            .request => c.SSL_VERIFY_PEER,
            .require => c.SSL_VERIFY_PEER | c.SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
        };
        c.SSL_set_verify(ssl, mode, null);
    }

    try conn.runHandshake(.{ .server = &options });
    conn.alpn_protocol = selectedAlpn(ssl, options.alpn_protocols);
    conn.strict_close_notify = options.strict_close_notify;
    if (c.SSL_get_servername(ssl, c.TLSEXT_NAMETYPE_host_name)) |name| conn.setServerName(std.mem.span(name));
    try conn.finishHandshake(options.gpa, options.keep_peer_certificates);
    return conn;
}

/// The versions in range, TLS 1.2 to 1.3 for a null bound, and with a
/// list of `suites`, only those it has a suite for: TLS 1.3's are its own,
/// every other is for the versions before it.
fn setVersions(ssl: *c.SSL, min: ?proto.Version, max: ?proto.Version, suites: ?[]const proto.CipherSuite) error{TlsInternalError}!void {
    var low: u16 = if (min) |v| @intFromEnum(v) else c.TLS1_2_VERSION;
    var high: u16 = if (max) |v| @intFromEnum(v) else c.TLS1_3_VERSION;
    if (suites) |list| {
        var tls13 = false;
        var older = false;
        for (list) |suite| {
            if (suite.version() == .tls_1_3) tls13 = true else older = true;
        }
        if (!tls13) high = @min(high, c.TLS1_2_VERSION);
        if (!older) low = @max(low, c.TLS1_3_VERSION);
    }
    if (low > high) return error.TlsInternalError;
    if (c.SSL_ctrl(ssl, c.SSL_CTRL_SET_MIN_PROTO_VERSION, low, null) != 1) return error.TlsInternalError;
    if (c.SSL_ctrl(ssl, c.SSL_CTRL_SET_MAX_PROTO_VERSION, high, null) != 1) return error.TlsInternalError;
}

/// Hands libssl the suites in our order: TLS 1.3's by their standard
/// names, the others by OpenSSL's. A suite OpenSSL does not know is
/// refused; one it knows but its policy rules out is left out.
fn setCipherSuites(ssl: *c.SSL, suites: []const proto.CipherSuite) error{TlsInternalError}!void {
    var tls13: [512]u8 = undefined;
    var tls12: [1024]u8 = undefined;
    var w13: Io.Writer = .fixed(&tls13);
    var w12: Io.Writer = .fixed(&tls12);
    for (suites) |suite| {
        var id: [2]u8 = undefined;
        std.mem.writeInt(u16, &id, @intFromEnum(suite), .big);
        const libssl_cipher = c.SSL_CIPHER_find(ssl, &id) orelse return error.TlsInternalError;
        const is_tls13 = suite.version() == .tls_1_3;
        const w = if (is_tls13) &w13 else &w12;
        const name = if (is_tls13) c.SSL_CIPHER_standard_name(libssl_cipher) else c.SSL_CIPHER_get_name(libssl_cipher);
        if (w.end > 0) w.writeByte(':') catch return error.TlsInternalError;
        w.writeAll(std.mem.span(name)) catch return error.TlsInternalError;
    }
    w13.writeByte(0) catch return error.TlsInternalError;
    w12.writeByte(0) catch return error.TlsInternalError;
    if (w13.end > 1 and c.SSL_set_ciphersuites(ssl, &tls13) != 1) return error.TlsInternalError;
    if (w12.end > 1 and c.SSL_set_cipher_list(ssl, &tls12) != 1) return error.TlsInternalError;
}

/// Whether the linked OpenSSL has X25519MLKEM768: 3.5 and newer. Without
/// it, the group is left out where it is listed.
pub fn hasMlKem() bool {
    return c.OpenSSL_version_num() >= 0x30500000;
}

/// The groups in our order, those OpenSSL lacks left out, by OpenSSL's
/// names. From OpenSSL 3.5 a `*` marks those to send key shares for;
/// before, the client sends one for the first group.
fn setGroups(ssl: *c.SSL, groups: []const proto.NamedGroup, key_shares: []const proto.NamedGroup) error{TlsInternalError}!void {
    var buf: [128]u8 = undefined;
    var w: Io.Writer = .fixed(&buf);
    var listed: [5]proto.NamedGroup = undefined;
    var n: usize = 0;
    for (groups) |group| {
        const name = switch (group) {
            .x25519_ml_kem768 => if (hasMlKem()) "X25519MLKEM768" else continue,
            .x25519 => "X25519",
            .secp256r1 => "P-256",
            .secp384r1 => "P-384",
            .secp521r1 => "P-521",
            else => continue,
        };
        // Each once, as the native client offers them.
        if (std.mem.indexOfScalar(proto.NamedGroup, listed[0..n], group) != null) continue;
        listed[n] = group;
        n += 1;
        if (n > 1) w.writeByte(':') catch return error.TlsInternalError;
        if (hasMlKem() and std.mem.indexOfScalar(proto.NamedGroup, key_shares, group) != null) w.writeByte('*') catch return error.TlsInternalError;
        w.writeAll(name) catch return error.TlsInternalError;
    }
    w.writeByte(0) catch return error.TlsInternalError;
    if (n == 0 or c.SSL_ctrl(ssl, c.SSL_CTRL_SET_GROUPS_LIST, 0, &buf) != 1) return error.TlsInternalError;
}

/// Sets a list of signature schemes, by their TLS names, which OpenSSL
/// takes as they are, but for one. `ctrl` says which: SSL_CTRL_SET_SIGALGS_LIST for
/// what the peer may sign with (a client) or what we sign with (a server),
/// SSL_CTRL_SET_CLIENT_SIGALGS_LIST for the other side of client
/// authentication. An empty list leaves libssl's default: with it, the
/// client presents no certificate (`pairSigns`), and a server refuses an
/// empty one.
fn setSchemes(ssl: *c.SSL, ctrl: c_int, schemes: []const proto.SignatureScheme) error{TlsInternalError}!void {
    if (schemes.len == 0) return;
    var buf: [512]u8 = undefined;
    var w: Io.Writer = .fixed(&buf);
    for (schemes, 0..) |scheme, i| {
        if (i > 0) w.writeByte(':') catch return error.TlsInternalError;
        // OpenSSL knows ecdsa_sha1 only by its older form of name.
        const name = if (scheme == .ecdsa_sha1) "ECDSA+SHA1" else std.enums.tagName(proto.SignatureScheme, scheme) orelse return error.TlsInternalError;
        w.writeAll(name) catch return error.TlsInternalError;
    }
    w.writeByte(0) catch return error.TlsInternalError;
    if (c.SSL_ctrl(ssl, ctrl, 0, &buf) != 1) return error.TlsInternalError;
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
    if (c.SSL_set_alpn_protos(ssl, wire.ptr, @intCast(wire.len)) != 0) return error.OutOfMemory;
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

/// The group the key exchange used. OpenSSL names it by NID, or for one
/// it has no NID for, by its TLS code point with a flag.
fn negotiatedGroup(ssl: *c.SSL) ?proto.NamedGroup {
    const nid = c.SSL_ctrl(ssl, c.SSL_CTRL_GET_NEGOTIATED_GROUP, 0, null);
    return switch (nid) {
        0 => null,
        c.NID_X25519 => .x25519,
        c.NID_X9_62_prime256v1 => .secp256r1,
        c.NID_secp384r1 => .secp384r1,
        c.NID_secp521r1 => .secp521r1,
        else => if (nid & c.TLSEXT_nid_unknown != 0) @enumFromInt(@as(u16, @truncate(@as(c_ulong, @bitCast(nid))))) else null,
    };
}

/// The scheme the peer signed the handshake with. OpenSSL tells the key
/// type and the hash apart; rsa_pss_pss schemes, which ztls does not
/// take, would read as rsa_pss_rsae.
fn peerSignatureScheme(ssl: *c.SSL) ?proto.SignatureScheme {
    var key_type: c_int = c.NID_undef;
    if (c.SSL_get_peer_signature_type_nid(ssl, &key_type) != 1) return null;
    var hash: c_int = c.NID_undef;
    _ = c.SSL_ctrl(ssl, c.SSL_CTRL_GET_PEER_SIGNATURE_NID, 0, &hash);
    return switch (key_type) {
        c.EVP_PKEY_ED25519 => .ed25519,
        c.EVP_PKEY_EC => switch (hash) {
            c.NID_sha256 => .ecdsa_secp256r1_sha256,
            c.NID_sha384 => .ecdsa_secp384r1_sha384,
            c.NID_sha512 => .ecdsa_secp521r1_sha512,
            c.NID_sha1 => .ecdsa_sha1,
            else => null,
        },
        c.EVP_PKEY_RSA_PSS => switch (hash) {
            c.NID_sha256 => .rsa_pss_rsae_sha256,
            c.NID_sha384 => .rsa_pss_rsae_sha384,
            c.NID_sha512 => .rsa_pss_rsae_sha512,
            else => null,
        },
        c.EVP_PKEY_RSA => switch (hash) {
            c.NID_sha256 => .rsa_pkcs1_sha256,
            c.NID_sha384 => .rsa_pkcs1_sha384,
            c.NID_sha512 => .rsa_pkcs1_sha512,
            c.NID_sha1 => .rsa_pkcs1_sha1,
            else => null,
        },
        else => null,
    };
}

/// Gives the connection a certificate chain and its key.
fn setCertificate(ssl: *c.SSL, pair: *const config.CertKeyPair) HandshakeError!void {
    const chain = c.OPENSSL_sk_new_null() orelse return error.OutOfMemory;
    defer c.OPENSSL_sk_pop_free(chain, freeX509);
    for (pair.chain[1..]) |der| {
        var cert = x509.Certificate.parseDer(der) catch return error.TlsInternalError;
        if (c.OPENSSL_sk_push(chain, cert.x509) == 0) {
            cert.deinit();
            return error.OutOfMemory;
        }
    }
    // libssl takes references of its own to all three.
    if (c.SSL_use_cert_and_key(ssl, pair.leaf.x509, pair.key.pkey, @ptrCast(chain), 1) != 1) {
        c.ERR_clear_error();
        return error.TlsInternalError;
    }
}

fn freeX509(ptr: ?*anyopaque) callconv(.c) void {
    c.X509_free(@ptrCast(ptr));
}

/// The peer's certificates as libssl holds them, leaf first. On the
/// server, libssl keeps the client's leaf apart from the rest.
const PeerChain = struct {
    leaf: ?*c.X509,
    rest: ?*c.OPENSSL_STACK,
    len: usize,

    fn get(chain: PeerChain, i: usize) *c.X509 {
        if (chain.leaf) |leaf| {
            if (i == 0) return leaf;
            return @ptrCast(c.OPENSSL_sk_value(chain.rest, @intCast(i - 1)).?);
        }
        return @ptrCast(c.OPENSSL_sk_value(chain.rest, @intCast(i)).?);
    }
};

fn peerChain(ssl: *c.SSL, side: proto.Side) PeerChain {
    const stack: ?*c.OPENSSL_STACK = @ptrCast(c.SSL_get_peer_cert_chain(ssl));
    const stack_len: usize = if (stack) |s| @intCast(c.OPENSSL_sk_num(s)) else 0;
    return switch (side) {
        .client => .{ .leaf = null, .rest = stack, .len = stack_len },
        .server => {
            const leaf = c.SSL_get0_peer_certificate(ssl) orelse return .{ .leaf = null, .rest = null, .len = 0 };
            return .{ .leaf = leaf, .rest = stack, .len = 1 + stack_len };
        },
    };
}

/// A certificate's DER, `gpa`'s.
fn derOf(gpa: std.mem.Allocator, cert: *c.X509) error{OutOfMemory}![]u8 {
    const len = c.i2d_X509(cert, null);
    if (len <= 0) return error.OutOfMemory;
    const der = try gpa.alloc(u8, @intCast(len));
    var p: [*c]u8 = der.ptr;
    if (c.i2d_X509(cert, &p) != len) {
        gpa.free(der);
        return error.OutOfMemory;
    }
    return der;
}

/// The type of key in a certificate, if ztls supports it.
fn keyType(cert: *const x509.Certificate) ?crypto.sig.KeyType {
    var key = cert.publicKey() catch return null;
    defer key.deinit();
    return key.key_type;
}

fn leafKeyType(leaf: *c.X509) ?crypto.sig.KeyType {
    const cert: x509.Certificate = .{ .x509 = leaf };
    return keyType(&cert);
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

/// Counts KeyUpdates and ClientHellos. libssl reports each whole
/// handshake message it reads or writes, and each record header.
fn messageCallback(write_p: c_int, version: c_int, content_type: c_int, buf: ?*const anyopaque, len: usize, ssl: ?*c.SSL, arg: ?*anyopaque) callconv(.c) void {
    _ = version;
    _ = arg;
    if (content_type != c.SSL3_RT_HANDSHAKE or len < 4) return;
    const bytes: [*]const u8 = @ptrCast(buf.?);
    const conn = connectionOf(ssl);
    if (bytes[0] == @intFromEnum(proto.HandshakeType.client_hello)) {
        conn.client_hellos +|= 1;
        return;
    }
    // Only a well-formed KeyUpdate, as the native side counts: libssl
    // reports a message it reads before it checks it.
    if (len != 5 or bytes[0] != @intFromEnum(proto.HandshakeType.key_update)) return;
    if (!std.mem.eql(u8, bytes[1..4], &.{ 0, 0, 1 }) or bytes[4] > 1) return;
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
    var schemes_buf: [all_schemes.len]proto.SignatureScheme = undefined;
    const theirs = peerSchemes(ssl.?, &schemes_buf);
    if (!pairSigns(ssl.?, pair, opt.signing_schemes orelse openssl_schemes, theirs)) return 1;
    if (c.SSL_version(ssl) < c.TLS1_3_VERSION and !certificateTypeRequested(ssl.?, pair.key.key_type)) return 1;
    setCertificate(ssl.?, pair) catch |err| {
        conn.callback_error = err;
        return 0;
    };
    return 1;
}

/// Checks the peer's chain as the native implementation does, in place of
/// libssl's own verification. libssl sends the alert for the error it is
/// left with.
fn verifyCallback(store_ctx: ?*c.X509_STORE_CTX, arg: ?*anyopaque) callconv(.c) c_int {
    _ = arg;
    const ssl: *c.SSL = @ptrCast(c.X509_STORE_CTX_get_ex_data(store_ctx, c.SSL_get_ex_data_X509_STORE_CTX_idx()).?);
    // A client with verification off; a server verifies only when it asks
    // for a certificate.
    if (c.SSL_get_verify_mode(ssl) == c.SSL_VERIFY_NONE) return 1;
    const conn = connectionOf(ssl);
    const untrusted: ?*c.OPENSSL_STACK = @ptrCast(c.X509_STORE_CTX_get0_untrusted(store_ctx));
    verifyPeer(conn, untrusted) catch |err| {
        conn.callback_error = err;
        c.X509_STORE_CTX_set_error(store_ctx, verifyErrorFor(proto.Alert.forLocalError(err) orelse .internal_error));
        return 0;
    };
    return 1;
}

/// An X.509 error libssl sends `alert` for.
fn verifyErrorFor(alert: proto.Alert) c_int {
    return switch (alert) {
        .bad_certificate => c.X509_V_ERR_CERT_REJECTED,
        .unsupported_certificate => c.X509_V_ERR_INVALID_PURPOSE,
        .certificate_expired => c.X509_V_ERR_CERT_HAS_EXPIRED,
        .certificate_revoked => c.X509_V_ERR_CERT_REVOKED,
        .unknown_ca => c.X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY,
        .decrypt_error => c.X509_V_ERR_CERT_SIGNATURE_FAILURE,
        .handshake_failure => c.X509_V_ERR_APPLICATION_VERIFICATION,
        else => c.X509_V_ERR_OUT_OF_MEM,
    };
}

/// libssl verifies the chain the peer sent, leaf first.
fn verifyPeer(conn: *Connection, sent: ?*c.OPENSSL_STACK) HandshakeError!void {
    const len: usize = if (sent) |s| @intCast(c.OPENSSL_sk_num(s)) else 0;
    if (len == 0) return error.TlsBadCertificate;
    if (len > config.CertKeyPair.max_chain_len) return error.TlsBadCertificate;
    var certs: [config.CertKeyPair.max_chain_len]x509.Certificate = undefined;
    var n: usize = 0;
    defer for (certs[0..n]) |*cert| cert.deinit();
    for (0..len) |i| {
        const cert: *c.X509 = @ptrCast(c.OPENSSL_sk_value(sent, @intCast(i)).?);
        if (c.X509_up_ref(cert) != 1) return error.OutOfMemory;
        certs[n] = .{ .x509 = cert };
        n += 1;
    }
    _ = keyType(&certs[0]) orelse return error.TlsUnsupportedCertificate;
    switch (conn.options) {
        .none => unreachable,
        .client => |opt| try policy.verifyChain(certs[0..n], opt.root_ca.?, .server, opt.host, policy.verifyTime(opt.io, opt.now)),
        .server => |opt| try policy.verifyChain(certs[0..n], opt.client_auth.?.root_ca, .client, null, policy.verifyTime(opt.io, opt.now)),
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
    // libssl has checked the list's encoding.
    const offered = in[0..in_len];
    for (ours) |name| {
        var i: usize = 0;
        while (i < offered.len) {
            const len = offered[i];
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

/// Picks the TLS 1.3 suite as the native server does, in our order, and
/// leaves libssl only that one. Runs for each ClientHello; after a
/// HelloRetryRequest the second must agree with the first.
fn clientHelloCallback(ssl: ?*c.SSL, alert: [*c]c_int, arg: ?*anyopaque) callconv(.c) c_int {
    _ = arg;
    const conn = connectionOf(ssl);
    var ids: [*c]const u8 = null;
    const ids_len = c.SSL_client_hello_get0_ciphers(ssl, &ids);
    const offered: []const u8 = if (ids_len == 0) &.{} else ids[0..ids_len];
    conn.legacy_auth = .of(ssl.?, offered);
    // With none in common, libssl finds none either and says so.
    const suite = policy.chooseSuite(conn.options.server.cipher_suites, offered, crypto.aead.hasAesHardware()) orelse return c.SSL_CLIENT_HELLO_SUCCESS;
    setCipherSuites(ssl.?, &.{suite}) catch |err| {
        conn.callback_error = err;
        alert.* = @intFromEnum(proto.Alert.internal_error);
        return c.SSL_CLIENT_HELLO_ERROR;
    };
    return c.SSL_CLIENT_HELLO_SUCCESS;
}

/// Picks the server's certificate as the native server picks it: the
/// first of `certificates` for the client's server name that it can
/// verify, else `auth`. libssl calls this once the ClientHello's
/// extensions are parsed, the signature algorithms and the server name
/// among them, with or without a server name, and sends the alert it is
/// given. Acknowledges no server name, as the native server does not.
fn serverNameCallback(ssl: ?*c.SSL, alert: ?*c_int, arg: ?*anyopaque) callconv(.c) c_int {
    _ = arg;
    const conn = connectionOf(ssl.?);
    selectCertificate(conn) catch |err| {
        conn.callback_error = err;
        alert.?.* = @intFromEnum(proto.Alert.forLocalError(err) orelse .internal_error);
        return c.SSL_TLSEXT_ERR_ALERT_FATAL;
    };
    return c.SSL_TLSEXT_ERR_NOACK;
}

/// Which certificates the suites before TLS 1.3 that both sides offer can
/// go with. In TLS 1.2 an Ed25519 key goes with ECDSA suites (RFC 8422).
const LegacyAuth = packed struct(u2) {
    rsa: bool = false,
    ecdsa: bool = false,

    fn of(ssl: *c.SSL, offered: []const u8) LegacyAuth {
        var auth: LegacyAuth = .{};
        const ours: *c.OPENSSL_STACK = @ptrCast(c.SSL_get_ciphers(ssl) orelse return auth);
        for (0..@intCast(c.OPENSSL_sk_num(ours))) |i| {
            const cipher: *const c.SSL_CIPHER = @ptrCast(c.OPENSSL_sk_value(ours, @intCast(i)).?);
            // TLS 1.3's suites name no key exchange.
            if (c.SSL_CIPHER_get_kx_nid(cipher) == c.NID_kx_any) continue;
            const id = c.SSL_CIPHER_get_protocol_id(cipher);
            var j: usize = 0;
            const theirs = while (j + 2 <= offered.len) : (j += 2) {
                if (std.mem.readInt(u16, offered[j..][0..2], .big) == id) break true;
            } else false;
            if (!theirs) continue;
            switch (c.SSL_CIPHER_get_auth_nid(cipher)) {
                c.NID_auth_rsa => auth.rsa = true,
                c.NID_auth_ecdsa => auth.ecdsa = true,
                else => {},
            }
        }
        return auth;
    }

    fn takesKey(auth: LegacyAuth, key_type: crypto.sig.KeyType) bool {
        return switch (key_type) {
            .rsa => auth.rsa,
            .ecdsa, .ed25519 => auth.ecdsa,
        };
    }
};

fn selectCertificate(conn: *Connection) HandshakeError!void {
    const opt = conn.options.server;
    const ssl = conn.ssl;
    const signing = opt.signing_schemes orelse openssl_schemes;
    var schemes_buf: [all_schemes.len]proto.SignatureScheme = undefined;
    const schemes = offeredSchemes(ssl, &schemes_buf);
    const server_name: ?[]const u8 = if (c.SSL_get_servername(ssl, c.TLSEXT_NAMETYPE_host_name)) |name| std.mem.span(name) else null;
    const pair = choice: {
        for (opt.certificates) |pair| {
            if (!pairSigns(ssl, pair, signing, schemes)) continue;
            if (c.SSL_version(ssl) < c.TLS1_3_VERSION and !conn.legacy_auth.takesKey(pair.key.key_type)) continue;
            if (server_name) |name| {
                if (!pair.leaf.matchesHost(name)) continue;
            }
            break :choice pair;
        }
        break :choice opt.auth orelse return error.TlsUnrecognizedName;
    };
    try setCertificate(ssl, pair);
}

/// The signature scheme rules of the version libssl negotiated, null
/// before TLS 1.2, which has none.
fn schemeRules(ssl: *const c.SSL) ?policy.Version {
    return switch (c.SSL_version(ssl)) {
        c.TLS1_3_VERSION => .tls13,
        c.TLS1_2_VERSION => .tls12,
        else => null,
    };
}

/// Whether `pair` can sign this handshake for a peer that takes `theirs`:
/// under one of `ours` that suits its key, or before TLS 1.2, which has
/// no schemes, with an RSA or ECDSA key. Empty `ours` signs nothing
/// either way.
fn pairSigns(ssl: *const c.SSL, pair: *const config.CertKeyPair, ours: []const proto.SignatureScheme, theirs: []const proto.SignatureScheme) bool {
    const version = schemeRules(ssl) orelse return ours.len > 0 and legacyKey(pair.key.key_type);
    return policy.selectScheme(ours, pair.key.key_type, theirs, version) != null;
}

/// Whether a CertificateRequest before TLS 1.3 asks for a key of this
/// type, as the native client checks: rsa_sign, or ecdsa_sign, which in
/// TLS 1.2 takes Ed25519 too (RFC 8422 §5.5).
fn certificateTypeRequested(ssl: *c.SSL, key_type: crypto.sig.KeyType) bool {
    var types: [*c]const u8 = null;
    const len = c.SSL_ctrl(ssl, c.SSL_CTRL_GET_CLIENT_CERT_TYPES, 0, @ptrCast(&types));
    if (len <= 0) return false;
    const wanted: u8 = switch (key_type) {
        .rsa => 1,
        .ecdsa, .ed25519 => 64,
    };
    return std.mem.indexOfScalar(u8, types[0..@intCast(len)], wanted) != null;
}

fn legacyKey(key_type: crypto.sig.KeyType) bool {
    return key_type == .rsa or key_type == .ecdsa;
}

/// The schemes for a null `signing_schemes` or `verify_schemes`: the
/// native defaults. TLS 1.2's SHA-1 ones only when listed.
const openssl_schemes = &config.default_signature_schemes;

/// Every scheme ztls knows, for collecting the peer's.
const all_schemes = &config.known_signature_schemes;

/// The peer's signature_algorithms that ztls supports, in its order, each
/// once: the client's in its ClientHello, or the server's in its
/// CertificateRequest.
fn peerSchemes(ssl: *c.SSL, buf: *[all_schemes.len]proto.SignatureScheme) []const proto.SignatureScheme {
    const len = c.SSL_get_sigalgs(ssl, -1, null, null, null, null, null);
    var n: usize = 0;
    var i: c_int = 0;
    while (i < len) : (i += 1) {
        var sig_byte: u8 = 0;
        var hash_byte: u8 = 0;
        _ = c.SSL_get_sigalgs(ssl, i, null, null, null, &sig_byte, &hash_byte);
        const scheme: proto.SignatureScheme = @enumFromInt(@as(u16, hash_byte) << 8 | sig_byte);
        if (std.mem.indexOfScalar(proto.SignatureScheme, all_schemes, scheme) == null) continue;
        if (std.mem.indexOfScalar(proto.SignatureScheme, buf[0..n], scheme) != null) continue;
        buf[n] = scheme;
        n += 1;
    }
    return buf[0..n];
}

/// The client's signature_algorithms, as `peerSchemes`. A TLS 1.2 client
/// that sends none takes the SHA-1 ones (RFC 5246 §7.4.1.4.1).
fn offeredSchemes(ssl: *c.SSL, buf: *[all_schemes.len]proto.SignatureScheme) []const proto.SignatureScheme {
    if (c.SSL_get_sigalgs(ssl, -1, null, null, null, null, null) == 0 and c.SSL_version(ssl) == c.TLS1_2_VERSION) {
        buf[0..2].* = .{ .rsa_pkcs1_sha1, .ecdsa_sha1 };
        return buf[0..2];
    }
    return peerSchemes(ssl, buf);
}

// The BIO between libssl and the transport's buffers. Its functions run
// inside a libssl call, under the connection's mutex, and never wait.

fn bioConnection(bio: ?*c.BIO) *Connection {
    return @ptrCast(@alignCast(c.BIO_get_data(bio).?));
}

fn clearRetry(bio: ?*c.BIO) void {
    c.BIO_clear_flags(bio, c.BIO_FLAGS_RWS | c.BIO_FLAGS_SHOULD_RETRY);
}

/// Hands libssl what the transport reader holds, if this call may read it.
fn bioRead(bio: ?*c.BIO, out: [*c]u8, len: c_int) callconv(.c) c_int {
    clearRetry(bio);
    if (len <= 0) return 0;
    const conn = bioConnection(bio);
    const bytes = if (conn.may_read) conn.input.buffered() else &.{};
    if (bytes.len == 0) {
        c.BIO_set_flags(bio, c.BIO_FLAGS_READ | c.BIO_FLAGS_SHOULD_RETRY);
        return -1;
    }
    const n = @min(bytes.len, @as(usize, @intCast(len)));
    @memcpy(out[0..n], bytes[0..n]);
    conn.tracker.feed(bytes[0..n]);
    conn.input.toss(n);
    return @intCast(n);
}

/// Takes all of what libssl wrote: into the transport writer's free space
/// if this call may write there and nothing waits in `spill` ahead of it,
/// the rest into `spill`.
fn bioWrite(bio: ?*c.BIO, data: [*c]const u8, len: c_int) callconv(.c) c_int {
    // This is the read direction's BIO too, so this clears a retry a read
    // left. libssl never writes between a failed read and asking about it.
    clearRetry(bio);
    if (len <= 0) return 0;
    const conn = bioConnection(bio);
    const bytes = data[0..@intCast(len)];
    var direct: usize = 0;
    if (conn.may_write and !conn.writtenPending()) {
        const space = conn.output.unusedCapacitySlice();
        direct = @min(space.len, bytes.len);
        @memcpy(space[0..direct], bytes[0..direct]);
        conn.output.advance(direct);
    }
    const rest = bytes[direct..];
    if (rest.len > 0 and c.BIO_write(conn.spill, rest.ptr, @intCast(rest.len)) != @as(c_int, @intCast(rest.len))) {
        // Out of memory: take none of it, so that no half record goes out.
        conn.output.end -= direct;
        return -1;
    }
    return len;
}

/// libssl flushes after each flight and alert; the task that owns the
/// transport writer does that, between calls.
fn bioCtrl(bio: ?*c.BIO, cmd: c_int, larg: c_long, parg: ?*anyopaque) callconv(.c) c_long {
    _ = .{ bio, larg, parg };
    return if (cmd == c.BIO_CTRL_FLUSH) 1 else 0;
}

// Process-wide state, made on first use.

const Globals = struct {
    client_ctx: *c.SSL_CTX,
    server_ctx: *c.SSL_CTX,
    ex_index: c_int,
    bio_method: *c.BIO_METHOD,
};

var globals_mutex: Io.Mutex = .init;
var globals_value: ?Globals = null;

fn globals(io: Io) error{ OutOfMemory, Canceled }!Globals {
    try globals_mutex.lock(io);
    defer globals_mutex.unlock(io);
    if (globals_value) |g| return g;
    defer c.ERR_clear_error();

    const client_ctx = try newCtx();
    errdefer c.SSL_CTX_free(client_ctx);
    const server_ctx = try newCtx();
    errdefer c.SSL_CTX_free(server_ctx);
    // No resumption yet, as in the native implementation: no tickets.
    if (c.SSL_CTX_set_num_tickets(server_ctx, 0) != 1) return error.OutOfMemory;
    // Nor TLS 1.2's tickets: no session is resumed.
    _ = c.SSL_CTX_set_options(server_ctx, ssl_op.no_ticket);
    c.SSL_CTX_set_alpn_select_cb(server_ctx, alpnSelectCallback, null);
    c.SSL_CTX_set_client_hello_cb(server_ctx, clientHelloCallback, null);
    if (c.SSL_CTX_callback_ctrl(server_ctx, c.SSL_CTRL_SET_TLSEXT_SERVERNAME_CB, @ptrCast(&serverNameCallback)) != 1) return error.OutOfMemory;

    const index = c.CRYPTO_get_ex_new_index(c.CRYPTO_EX_INDEX_SSL, 0, null, null, null, null);
    if (index < 0) return error.OutOfMemory;
    const bio_type = c.BIO_get_new_index();
    if (bio_type < 0) return error.OutOfMemory;
    const bio_method = c.BIO_meth_new(bio_type | c.BIO_TYPE_SOURCE_SINK, "ztls transport") orelse return error.OutOfMemory;
    errdefer c.BIO_meth_free(bio_method);
    if (c.BIO_meth_set_read(bio_method, bioRead) != 1 or
        c.BIO_meth_set_write(bio_method, bioWrite) != 1 or
        c.BIO_meth_set_ctrl(bio_method, bioCtrl) != 1) return error.OutOfMemory;
    globals_value = .{ .client_ctx = client_ctx, .server_ctx = server_ctx, .ex_index = index, .bio_method = bio_method };
    return globals_value.?;
}

fn newCtx() error{OutOfMemory}!*c.SSL_CTX {
    const ctx = c.SSL_CTX_new(c.TLS_method()) orelse return error.OutOfMemory;
    _ = c.SSL_CTX_ctrl(ctx, c.SSL_CTRL_SET_SESS_CACHE_MODE, c.SSL_SESS_CACHE_OFF, null);
    // No renegotiation, as in the native implementation and AWS-LC.
    _ = c.SSL_CTX_set_options(ctx, ssl_op.no_renegotiation);
    // The options decide which versions, suites and signatures are
    // allowed, in every implementation; the system's security level
    // would refuse what they ask for, a client's fallback to TLS 1.0 say.
    c.SSL_CTX_set_security_level(ctx, 0);
    // Our own verification in place of libssl's, on both sides.
    c.SSL_CTX_set_cert_verify_callback(ctx, verifyCallback, null);
    return ctx;
}

// Helpers

/// OpenSSL's SSL_OP_ flags, whose macros translate-c cannot carry over.
const ssl_op = struct {
    const no_ticket: u64 = 1 << 14;
    const cipher_server_preference: u64 = 1 << 22;
    const no_renegotiation: u64 = 1 << 30;
};

/// A failure of the handshake as one of a connection's, for those that can
/// only come after it.
fn asFailure(err: HandshakeError) Failure {
    inline for (comptime std.meta.fieldNames(Failure)) |name| {
        if (err == @field(HandshakeError, name)) return @field(Failure, name);
    }
    return error.TlsInternalError;
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
