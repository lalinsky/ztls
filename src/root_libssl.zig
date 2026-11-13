//! ztls on AWS-LC's libssl (`-Dimpl=libssl`): the API of the native
//! implementation, with libssl running the protocol.
//!
//! `client` and `server` run a handshake over a transport's reader and
//! writer and return a `Connection`, whose `reader` and `writer` carry
//! cleartext.

const std = @import("std");

pub const crypto = @import("crypto.zig");
pub const protocol = @import("protocol.zig");
pub const config = @import("config.zig");
const connection = @import("libssl/connection.zig");

/// For code written to tls.zig's API shape that adapts at comptime to
/// the few places this library differs: check `@hasDecl(tls, "is_ztls")`.
pub const is_ztls = true;

pub const Connection = connection.Connection;
pub const TrustStore = config.TrustStore;
pub const CertKeyPair = config.CertKeyPair;
pub const Signer = config.Signer;
pub const Error = connection.HandshakeError;

/// The transport reader's buffer must be at least this long.
pub const input_buffer_len = connection.input_buffer_len;
/// The transport writer's buffer must be at least this long.
pub const output_buffer_len = connection.output_buffer_len;

/// Runs the client side of a handshake over `input` and `output`, the
/// transport's ciphertext reader and writer. On failure the peer is told
/// why when that is something we found.
///
/// The Connection comes back by value; its readers and writers point at
/// it, so it must not move once they exist.
pub const client = connection.client;

/// Runs the server side of a handshake over `input` and `output`.
pub const server = connection.server;

test {
    std.testing.refAllDecls(@This());
    _ = @import("api_test.zig");
    _ = @import("interop_test.zig");
}
