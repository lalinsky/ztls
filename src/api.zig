//! What the public API of both implementations is made of, so that they
//! agree on it: the errors, the states of a connection's directions, and
//! the transport buffer sizes.

const std = @import("std");
const proto = @import("protocol.zig");

/// What a handshake can fail with. `EndOfStream` is the peer going away
/// before it was done; `ReadFailed`/`WriteFailed` are the transport's,
/// whose own error says why.
pub const Error = proto.LocalError || proto.Alert.Error || error{
    ReadFailed,
    WriteFailed,
    EndOfStream,
    OutOfMemory,
};

/// What a read or write can fail with: the transport's own failure,
/// something the record layer found, or an alert the peer sent.
pub const Failure = error{
    TlsConnectionTruncated,
    TlsConnectionFailed,
    TlsRecordOverflow,
    TlsBadRecordMac,
    TlsDecodeError,
    TlsUnexpectedMessage,
    TlsIllegalParameter,
    TlsInternalError,
    TlsNoRenegotiation,
    TlsProtocolVersion,
} || proto.Alert.Error;
/// What a read can fail with: the transport reader's failure, which does
/// not end the connection, or a `Failure`, which does.
pub const ReadError = error{ReadFailed} || Failure;
/// What a write can fail with: the transport writer's failure or a
/// `Failure`, the read side's included, since that is where its alert
/// goes out.
pub const WriteError = error{WriteFailed} || Failure;

pub const State = enum(u8) {
    open,
    /// close_notify went this way, or the transport ended cleanly.
    closed,
    /// A failure ended this direction.
    failed,
};

const header_len = 5;
const max_plaintext_len = 1 << 14;

/// The transport reader's buffer must hold one whole record: the header
/// and the longest encrypted body a peer may send (RFC 9846 §5.2).
pub const input_buffer_len: usize = header_len + max_plaintext_len + 256;

/// The transport writer's buffer must hold one whole sealed record and, in
/// TLS 1.3, the KeyUpdate that may have to go out ahead of it. A TLS 1.3
/// record adds its content type and a 16-byte tag; the KeyUpdate is a
/// record of its own around a 5-byte message. TLS 1.2 adds less: an 8-byte
/// explicit nonce and the tag.
pub const output_buffer_len: usize = @max(
    (header_len + max_plaintext_len + 1 + 16) + (header_len + 5 + 1 + 16),
    header_len + max_plaintext_len + 8 + 16,
);
