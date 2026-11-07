//! What a side brings to a handshake: its certificate and key, the peers
//! it trusts, and the options of `client` and `server`.

const std = @import("std");
const Allocator = std.mem.Allocator;
const crypto = @import("crypto.zig");
const proto = @import("protocol.zig");

pub const TrustStore = crypto.x509.TrustStore;
pub const PrivateKey = crypto.sig.PrivateKey;
pub const Certificate = crypto.x509.Certificate;

/// A certificate chain, leaf first, with the leaf's private key: what a
/// server presents, or a client under mutual TLS. Built once and shared
/// read-only by any number of connections.
pub const CertKeyPair = struct {
    allocator: Allocator,
    /// Each certificate's DER, leaf first, as sent in the Certificate
    /// message.
    chain: []const []const u8,
    /// The leaf, parsed: its key type picks the signature algorithm.
    leaf: Certificate,
    key: PrivateKey,

    /// Certificates in a chain, including the leaf.
    pub const max_chain_len = 16;

    pub const Error = error{
        /// No certificate in the PEM, or one that does not parse.
        InvalidCertificate,
        /// More than `max_chain_len` certificates.
        ChainTooLong,
        /// The private key is not the leaf's.
        KeyMismatch,
    } || crypto.sig.ParseError;

    /// From PEM text: every CERTIFICATE block of `cert_pem`, leaf first,
    /// and the first private key block of `key_pem`. Encrypted keys are
    /// not supported.
    pub fn fromSlice(allocator: Allocator, cert_pem: []const u8, key_pem: []const u8) Error!CertKeyPair {
        var chain: std.ArrayList([]const u8) = .empty;
        errdefer {
            for (chain.items) |der| allocator.free(der);
            chain.deinit(allocator);
        }
        var it = crypto.pem.Iterator.init(cert_pem);
        while (try it.next()) |block| {
            if (!std.mem.eql(u8, block.label, "CERTIFICATE")) continue;
            if (chain.items.len == max_chain_len) return error.ChainTooLong;
            const buf = try allocator.alloc(u8, block.decodedSizeUpperBound());
            errdefer allocator.free(buf);
            const der = try block.decode(buf);
            const exact = try allocator.realloc(buf, der.len);
            try chain.append(allocator, exact);
        }
        if (chain.items.len == 0) return error.InvalidCertificate;

        var leaf = try Certificate.parseDer(chain.items[0]);
        errdefer leaf.deinit();
        var key = try PrivateKey.parsePem(allocator, key_pem);
        errdefer key.deinit();
        if (!leaf.matchesPrivateKey(&key)) return error.KeyMismatch;

        return .{
            .allocator = allocator,
            .chain = try chain.toOwnedSlice(allocator),
            .leaf = leaf,
            .key = key,
        };
    }

    pub fn deinit(self: *CertKeyPair) void {
        for (self.chain) |der| self.allocator.free(der);
        self.allocator.free(self.chain);
        self.leaf.deinit();
        self.key.deinit();
        self.* = undefined;
    }
};

/// A server's own choice of certificate. Called during the handshake on
/// the connection's task, so it must not block or yield. The pair it
/// returns must outlive the handshake, and the slices in `Hello` are
/// valid only during the call. Returning a pair whose key the client
/// cannot verify fails the handshake (handshake_failure) rather than
/// falling back to `certificates`; returning null falls back.
pub const SelectCertificate = struct {
    context: ?*anyopaque = null,
    callback: *const fn (context: ?*anyopaque, hello: Hello) ?*const CertKeyPair,

    /// What the ClientHello says that bears on the choice.
    pub const Hello = struct {
        /// The server_name extension's host name, if any.
        server_name: ?[]const u8,
        /// Whether the client can verify signatures by a key of this type.
        accepts: *const fn (hello: *const Hello, key_type: crypto.sig.KeyType) bool,
        schemes: []const proto.SignatureScheme,

        pub fn acceptsKey(hello: *const Hello, key_type: crypto.sig.KeyType) bool {
            return hello.accepts(hello, key_type);
        }
    };
};

/// Whether a server asks for a client certificate, and what it accepts.
pub const ClientAuth = struct {
    /// What a client certificate must chain to.
    root_ca: *const TrustStore,
    auth_type: Type = .require,

    pub const Type = enum {
        /// Ask, but accept a client that sends none.
        request,
        /// Ask, and refuse a client that sends none.
        require,
    };
};

/// The groups a client supports, in preference order.
pub const default_named_groups = [_]proto.NamedGroup{ .x25519_ml_kem768, .x25519, .secp256r1 };
/// A server takes secp384r1 too, for clients that offer nothing better.
pub const default_server_named_groups = default_named_groups ++ [_]proto.NamedGroup{.secp384r1};
/// The groups a client sends key shares for in its first ClientHello:
/// the ones a server is likely to pick, so a HelloRetryRequest is rare.
pub const default_key_shares = [_]proto.NamedGroup{ .x25519_ml_kem768, .x25519 };

pub const Client = struct {
    /// For the handshake's working memory: the peer's messages are
    /// reassembled in it. Nothing is kept after the handshake.
    allocator: Allocator,
    /// The server's name, sent as SNI and checked against its
    /// certificate. An IP literal is checked against the certificate's IP
    /// addresses instead and sent as no SNI.
    host: []const u8,
    /// What the server's certificate must chain to. Required unless
    /// `insecure_skip_verify`.
    root_ca: ?*const TrustStore = null,
    /// Accept any certificate, checking nothing. For tests only.
    insecure_skip_verify: bool = false,
    /// A certificate to present if the server asks for one.
    auth: ?*const CertKeyPair = null,
    cipher_suites: []const proto.CipherSuite = &proto.CipherSuite.all,
    named_groups: []const proto.NamedGroup = &default_named_groups,
    /// Groups to send key shares for; each must be in `named_groups`.
    key_shares: []const proto.NamedGroup = &default_key_shares,
    /// Offered through ALPN, in preference order. Empty sends no ALPN.
    alpn_protocols: []const []const u8 = &.{},
    /// For certificate validity.
    now: std.Io.Timestamp,
    /// Treat a transport that ends without close_notify as truncated even
    /// between records.
    strict_close_notify: bool = false,
    /// The longest handshake message accepted from the peer; the
    /// Certificate message is the one that gets big.
    max_handshake_message_len: usize = 64 * 1024,
};

pub const Server = struct {
    /// For the handshake's working memory; nothing is kept afterwards.
    allocator: Allocator,
    /// What the server presents when nothing in `certificates` or from
    /// `select_certificate` fits. Null for a server with no certificate,
    /// which no client accepts in v1.
    auth: ?*const CertKeyPair,
    /// Further certificates, picked by the server name the client asks
    /// for and by the signature algorithms it accepts: the first whose
    /// leaf is for that name and whose key the client can verify. With
    /// no server name, the first whose key the client can verify.
    certificates: []const *const CertKeyPair = &.{},
    /// Picks the certificate for a connection, before `certificates` and
    /// `auth` are tried. Null leaves the choice to them.
    select_certificate: ?SelectCertificate = null,
    client_auth: ?ClientAuth = null,
    cipher_suites: []const proto.CipherSuite = &proto.CipherSuite.all,
    named_groups: []const proto.NamedGroup = &default_server_named_groups,
    /// Supported, in preference order. A client whose offer shares none
    /// is refused with no_application_protocol; one that offers none
    /// gets none. Empty disables ALPN.
    alpn_protocols: []const []const u8 = &.{},
    /// For client certificate validity.
    now: std.Io.Timestamp,
    strict_close_notify: bool = false,
    max_handshake_message_len: usize = 64 * 1024,
};

const testing = std.testing;

test "CertKeyPair from the test PKI" {
    var pair = try CertKeyPair.fromSlice(testing.allocator, @embedFile("testdata/pki/server-chain.pem"), @embedFile("testdata/pki/server-chain.key"));
    defer pair.deinit();
    try testing.expectEqual(2, pair.chain.len); // leaf and intermediate
    try testing.expectEqual(crypto.sig.KeyType{ .ecdsa = .p384 }, pair.key.key_type);
    var leaf = try Certificate.parseDer(pair.chain[0]);
    defer leaf.deinit();
    try testing.expect(leaf.matchesPrivateKey(&pair.key));

    var rsa = try CertKeyPair.fromSlice(testing.allocator, @embedFile("testdata/pki/server-rsa.pem"), @embedFile("testdata/pki/server-rsa.key"));
    defer rsa.deinit();
    try testing.expectEqual(1, rsa.chain.len);
}

test "CertKeyPair refuses a key that is not the leaf's, and no certificate" {
    try testing.expectError(error.KeyMismatch, CertKeyPair.fromSlice(testing.allocator, @embedFile("testdata/pki/server-ec.pem"), @embedFile("testdata/pki/client.key")));
    try testing.expectError(error.InvalidCertificate, CertKeyPair.fromSlice(testing.allocator, @embedFile("testdata/pki/server-ec.key"), @embedFile("testdata/pki/server-ec.key")));
    try testing.expectError(error.InvalidKey, CertKeyPair.fromSlice(testing.allocator, @embedFile("testdata/pki/server-ec.pem"), @embedFile("testdata/pki/server-ec.pem")));
}
