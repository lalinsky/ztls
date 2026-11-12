//! ztls on AWS-LC's libssl (`-Dimpl=libssl`).
//!
//! Work in progress: so far only the build, checked by a handshake between
//! two libssl connections in memory.

const std = @import("std");
const c = @import("c");

const testing = std.testing;

fn loadCert(pem: []const u8) !*c.X509 {
    const bio = c.BIO_new_mem_buf(pem.ptr, @intCast(pem.len)) orelse return error.OutOfMemory;
    defer _ = c.BIO_free(bio);
    return c.PEM_read_bio_X509(bio, null, null, null) orelse error.InvalidCertificate;
}

fn loadKey(pem: []const u8) !*c.EVP_PKEY {
    const bio = c.BIO_new_mem_buf(pem.ptr, @intCast(pem.len)) orelse return error.OutOfMemory;
    defer _ = c.BIO_free(bio);
    return c.PEM_read_bio_PrivateKey(bio, null, null, null) orelse error.InvalidKey;
}

/// One handshake step; true once it is done, an error unless it only waits
/// for the peer.
fn step(ssl: *c.SSL) !bool {
    const rc = c.SSL_do_handshake(ssl);
    if (rc == 1) return true;
    if (c.SSL_get_error(ssl, rc) == c.SSL_ERROR_WANT_READ) return false;
    return error.HandshakeFailed;
}

test "a libssl client and server complete a handshake in memory" {
    defer c.ERR_clear_error();

    const cert = try loadCert(@embedFile("testdata/pki/server-ec.pem"));
    defer c.X509_free(cert);
    const key = try loadKey(@embedFile("testdata/pki/server-ec.key"));
    defer c.EVP_PKEY_free(key);
    const ca = try loadCert(@embedFile("testdata/pki/ca.pem"));
    defer c.X509_free(ca);

    const server_ctx = c.SSL_CTX_new(c.TLS_method()) orelse return error.OutOfMemory;
    defer c.SSL_CTX_free(server_ctx);
    try testing.expectEqual(1, c.SSL_CTX_use_certificate(server_ctx, cert));
    try testing.expectEqual(1, c.SSL_CTX_use_PrivateKey(server_ctx, key));

    const client_ctx = c.SSL_CTX_new(c.TLS_method()) orelse return error.OutOfMemory;
    defer c.SSL_CTX_free(client_ctx);
    try testing.expectEqual(1, c.X509_STORE_add_cert(c.SSL_CTX_get_cert_store(client_ctx), ca));
    c.SSL_CTX_set_verify(client_ctx, c.SSL_VERIFY_PEER, null);

    const server = c.SSL_new(server_ctx) orelse return error.OutOfMemory;
    defer c.SSL_free(server);
    const client = c.SSL_new(client_ctx) orelse return error.OutOfMemory;
    defer c.SSL_free(client);

    var server_bio: ?*c.BIO = null;
    var client_bio: ?*c.BIO = null;
    try testing.expectEqual(1, c.BIO_new_bio_pair(&server_bio, 0, &client_bio, 0));
    c.SSL_set_bio(server, server_bio, server_bio);
    c.SSL_set_bio(client, client_bio, client_bio);
    c.SSL_set_accept_state(server);
    c.SSL_set_connect_state(client);
    try testing.expectEqual(1, c.SSL_set_tlsext_host_name(client, "localhost"));
    try testing.expectEqual(1, c.SSL_set1_host(client, "localhost"));

    var client_done = false;
    var server_done = false;
    var rounds: usize = 0;
    while (!(client_done and server_done)) : (rounds += 1) {
        if (rounds == 10) return error.HandshakeStalled;
        if (!client_done) client_done = try step(client);
        if (!server_done) server_done = try step(server);
    }

    try testing.expectEqual(c.TLS1_3_VERSION, c.SSL_version(client));
    try testing.expectEqual(c.X509_V_OK, c.SSL_get_verify_result(client));

    const message = "hello over libssl";
    try testing.expectEqual(@as(c_int, message.len), c.SSL_write(client, message, message.len));
    var buf: [64]u8 = undefined;
    const n = c.SSL_read(server, &buf, buf.len);
    try testing.expectEqualStrings(message, buf[0..@intCast(n)]);
}
