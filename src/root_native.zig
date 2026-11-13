//! ztls: TLS 1.3, and a TLS 1.2 client, on AWS-LC's libcrypto.
//!
//! `client` and `server` run a handshake over a transport's reader and
//! writer and return a `Connection`, whose `reader`, `writer` and
//! `writerInPlace` carry cleartext.

const std = @import("std");
const Io = std.Io;

pub const crypto = @import("crypto.zig");
pub const protocol = @import("protocol.zig");
pub const codec = @import("native/codec.zig");
pub const key_schedule = @import("native/key_schedule.zig");
pub const cipher = @import("native/cipher.zig");
pub const connection = @import("native/connection.zig");
pub const config = @import("config.zig");
pub const handshake = @import("native/handshake.zig");
const handshake_client = @import("native/handshake_client.zig");
const handshake_server = @import("native/handshake_server.zig");

/// For code written to tls.zig's API shape that adapts at comptime to
/// the few places this library differs, such as `gpa` in the
/// options and the trust store type: check `@hasDecl(tls, "is_ztls")`.
pub const is_ztls = true;

pub const Connection = connection.Connection;
pub const TrustStore = config.TrustStore;
pub const CertKeyPair = config.CertKeyPair;
pub const Signer = config.Signer;
pub const Error = handshake.Error;

/// The transport reader's buffer must be at least this long: one whole
/// record.
pub const input_buffer_len = connection.input_buffer_len;
/// The transport writer's buffer must be at least this long: one whole
/// sealed record and the KeyUpdate that may go ahead of it.
pub const output_buffer_len = connection.output_buffer_len;

/// Runs the client side of a handshake over `input` and `output`, the
/// transport's ciphertext reader and writer. On failure the peer is told
/// why when that is something we found.
///
/// The Connection comes back by value; its readers and writers point at
/// it, so it must not move once they exist. The copy the handshake made
/// on its stack keeps the keys as residue; that is accepted, like the
/// shared secrets on the way to the key schedule.
pub fn client(input: *Io.Reader, output: *Io.Writer, options: config.Client) Error!Connection {
    var conn = Connection.init(input, output, .client);
    errdefer conn.deinit();
    try handshake_client.run(&conn, options);
    return conn;
}

/// Runs the server side of a handshake over `input` and `output`.
pub fn server(input: *Io.Reader, output: *Io.Writer, options: config.Server) Error!Connection {
    var conn = Connection.init(input, output, .server);
    errdefer conn.deinit();
    try handshake_server.run(&conn, options);
    return conn;
}

test {
    std.testing.refAllDecls(@This());
    _ = @import("api_test.zig");
    _ = @import("interop_test.zig");
    _ = @import("native/handshake_client_tls12.zig");
}
