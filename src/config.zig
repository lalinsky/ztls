//! What a side brings to a handshake: its certificate and key, the peers
//! it trusts, and the options of `client` and `server`.

const std = @import("std");
const Allocator = std.mem.Allocator;
const crypto = @import("crypto.zig");
const proto = @import("protocol.zig");

pub const TrustStore = crypto.x509.TrustStore;
pub const PrivateKey = crypto.sig.PrivateKey;
pub const Certificate = crypto.x509.Certificate;

/// Signs CertificateVerify in the library's stead, so the handshake's
/// task can hand the work to a thread pool.
pub const Signer = struct {
    context: ?*anyopaque = null,
    /// Signs `message` with `key` under `algorithm` into `out`, and
    /// returns the signature as a slice of `out`. The message is the
    /// framed CertificateVerify content; in TLS 1.2, a client's is the
    /// handshake messages so far, which can run long, and under
    /// `-Dimpl=libssl` a server's is its ServerKeyExchange parameters.
    /// Runs on the handshake's task and may block or suspend; it must not
    /// touch the connection. Any error fails the handshake with
    /// internal_error.
    ///
    /// A pair with a signer needs TLS 1.2 or newer, whose signatures name
    /// their algorithm, and a server presenting one does no RSA key
    /// exchange, which decrypts with the key: under `-Dimpl=libssl` such a
    /// pair is passed over before TLS 1.2, and RSA key exchange is not
    /// offered with it.
    sign: *const fn (context: ?*anyopaque, key: *const PrivateKey, algorithm: crypto.sig.Algorithm, message: []const u8, out: []u8) anyerror![]u8,
};

/// A certificate chain, leaf first, with the leaf's private key: what a
/// server presents, or a client under mutual TLS. Built once and shared
/// read-only by any number of connections.
pub const CertKeyPair = struct {
    /// Each certificate's DER, leaf first, as sent in the Certificate
    /// message.
    chain: []const []const u8,
    /// The leaf, parsed: its key type picks the signature algorithm.
    leaf: Certificate,
    key: PrivateKey,
    /// Signs in place of `key` on the handshake's task, when set.
    signer: ?Signer = null,

    /// Certificates in a chain, including the leaf.
    pub const max_chain_len = 64;

    pub const Error = error{
        /// No certificate in the PEM, or one that does not parse.
        InvalidCertificate,
        /// More than `max_chain_len` certificates.
        ChainTooLong,
        /// The private key is not the leaf's.
        KeyMismatch,
    } || crypto.sig.ParseError;

    pub const FileError = Error || std.Io.Dir.ReadFileAllocError;

    /// The most a certificate or key file may be.
    pub const max_file_len = 1 << 20;

    /// From two PEM files under `dir`: the chain, leaf first, and the
    /// private key. See `fromSlice`.
    pub fn fromFilePath(allocator: Allocator, io: std.Io, dir: std.Io.Dir, cert_path: []const u8, key_path: []const u8) FileError!CertKeyPair {
        const cert_pem = try dir.readFileAlloc(io, cert_path, allocator, .limited(max_file_len));
        defer allocator.free(cert_pem);
        const key_pem = try readSecretFile(allocator, io, dir, key_path);
        defer {
            std.crypto.secureZero(u8, key_pem);
            allocator.free(key_pem);
        }
        return fromSlice(allocator, cert_pem, key_pem);
    }

    /// Reads a whole file of at most `max_file_len` bytes, wiping every
    /// buffer the contents pass through on the way, which `readFileAlloc`
    /// does not promise when it has to grow one: a key may come from a
    /// pipe or a secret manager's pseudo-file whose size is not known up
    /// front.
    fn readSecretFile(allocator: Allocator, io: std.Io, dir: std.Io.Dir, sub_path: []const u8) FileError![]u8 {
        const file = try dir.openFile(io, sub_path, .{});
        defer file.close(io);
        var reader = file.reader(io, &.{});

        var buf = try allocator.alloc(u8, 4096);
        defer {
            std.crypto.secureZero(u8, buf);
            allocator.free(buf);
        }
        var len: usize = 0;
        while (true) {
            len += reader.interface.readSliceShort(buf[len..]) catch return reader.err.?;
            // A short read is the end of the file.
            if (len < buf.len) break;
            if (buf.len > max_file_len) return error.StreamTooLong;
            const bigger = try allocator.alloc(u8, @min(buf.len * 2, max_file_len + 1));
            @memcpy(bigger[0..len], buf);
            std.crypto.secureZero(u8, buf);
            allocator.free(buf);
            buf = bigger;
        }
        const exact = try allocator.alloc(u8, len);
        @memcpy(exact, buf[0..len]);
        return exact;
    }

    /// `fromFilePath` with absolute paths, which the caller has checked, as
    /// with std's own `Absolute` functions.
    pub fn fromFilePathAbsolute(allocator: Allocator, io: std.Io, cert_path: []const u8, key_path: []const u8) FileError!CertKeyPair {
        std.debug.assert(std.Io.Dir.path.isAbsolute(cert_path));
        std.debug.assert(std.Io.Dir.path.isAbsolute(key_path));
        return fromFilePath(allocator, io, .cwd(), cert_path, key_path);
    }

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
            try chain.ensureUnusedCapacity(allocator, 1);
            const buf = try allocator.alloc(u8, block.decodedSizeUpperBound());
            errdefer allocator.free(buf);
            const der = try block.decode(buf);
            chain.appendAssumeCapacity(try allocator.realloc(buf, der.len));
        }
        if (chain.items.len == 0) return error.InvalidCertificate;

        var leaf = try Certificate.parseDer(chain.items[0]);
        errdefer leaf.deinit();
        var key = try PrivateKey.parsePem(allocator, key_pem);
        errdefer key.deinit();
        if (!leaf.matchesPrivateKey(&key)) return error.KeyMismatch;

        return .{
            .chain = try chain.toOwnedSlice(allocator),
            .leaf = leaf,
            .key = key,
        };
    }

    /// `allocator` is the one given to `fromSlice` or `fromFilePath`.
    pub fn deinit(self: *CertKeyPair, allocator: Allocator) void {
        for (self.chain) |der| allocator.free(der);
        allocator.free(self.chain);
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
        /// Whether the client can verify signatures by a key of this type,
        /// under a scheme in the server's `signing_schemes`. Before TLS
        /// 1.2, which has no signature schemes, any RSA or ECDSA key.
        accepts: *const fn (hello: *const Hello, key_type: crypto.sig.KeyType) bool,
        /// The client's signature_algorithms that ztls supports, in the
        /// client's order. In TLS 1.2 a client that sends none takes the
        /// SHA-1 ones; before TLS 1.2, empty.
        schemes: []const proto.SignatureScheme,
        /// The server's `signing_schemes`, or the implementation's default,
        /// for `accepts`; a callback that uses `acceptsKey` need not look
        /// at it.
        signing_schemes: []const proto.SignatureScheme,

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

/// TLS 1.3's suites, then TLS 1.2's, for servers that have nothing newer.
pub const default_cipher_suites = proto.CipherSuite.all ++ proto.CipherSuite.tls12;
/// `default_cipher_suites` with ChaCha20-Poly1305 first in each version,
/// what a client offers on a machine without AES instructions.
pub const default_cipher_suites_chacha_first = [_]proto.CipherSuite{
    .chacha20_poly1305_sha256,
    .aes_128_gcm_sha256,
    .aes_256_gcm_sha384,
    .ecdhe_ecdsa_with_chacha20_poly1305_sha256,
    .ecdhe_rsa_with_chacha20_poly1305_sha256,
    .ecdhe_ecdsa_with_aes_128_gcm_sha256,
    .ecdhe_rsa_with_aes_128_gcm_sha256,
    .ecdhe_ecdsa_with_aes_256_gcm_sha384,
    .ecdhe_rsa_with_aes_256_gcm_sha384,
};
/// The server's preference when ChaCha20-Poly1305 is the better choice.
pub const default_server_cipher_suites_chacha_first = default_cipher_suites_chacha_first[0..proto.CipherSuite.all.len].*;
/// The groups a client supports, in preference order.
pub const default_named_groups = [_]proto.NamedGroup{ .x25519_ml_kem768, .x25519, .secp256r1, .secp384r1 };
pub const default_server_named_groups = default_named_groups;
/// The groups a client sends key shares for in its first ClientHello:
/// the ones a server is likely to pick, so a HelloRetryRequest is rare.
pub const default_key_shares = [_]proto.NamedGroup{ .x25519_ml_kem768, .x25519 };
/// The signature schemes the native implementation uses by default, in
/// preference order, for both `verify_schemes` and `signing_schemes`. In
/// TLS 1.3 the rsa_pkcs1 ones only tell the peer which certificate
/// signatures we accept; they never sign a CertificateVerify. In TLS 1.2
/// they sign handshakes too.
pub const default_signature_schemes = [_]proto.SignatureScheme{
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

/// Every signature scheme ztls implements: the default ones, then TLS
/// 1.2's SHA-1 ones, for peers that take nothing else. In TLS 1.3 those
/// sign nothing.
pub const known_signature_schemes = default_signature_schemes ++ [_]proto.SignatureScheme{ .ecdsa_sha1, .rsa_pkcs1_sha1 };

pub const Client = struct {
    /// What the connection waits with: under `-Dimpl=libssl`, the reading
    /// and the writing task take turns at libssl's state under a lock that
    /// parks the waiting task rather than its thread. The native engine
    /// does not use it.
    io: std.Io,
    /// For the handshake's working memory, such as the peer's messages
    /// while they are reassembled. Nothing is kept after the handshake unless
    /// `keep_peer_certificates` is set; then it must stay valid until
    /// `Connection.deinit()`.
    gpa: Allocator,
    /// The server's name, sent as SNI and checked against its
    /// certificate. An IP literal is checked against the certificate's IP
    /// addresses instead and sent as no SNI. At most 255 bytes, not
    /// starting with a dot, and empty only with `insecure_skip_verify`.
    host: []const u8,
    /// What the server's certificate must chain to. Required unless
    /// `insecure_skip_verify`.
    root_ca: ?*const TrustStore = null,
    /// Accept any certificate, checking nothing. For tests only.
    insecure_skip_verify: bool = false,
    /// A certificate to present if the server asks for one.
    auth: ?*const CertKeyPair = null,
    /// The lowest and highest versions offered. Null is the
    /// implementation's own bound: the native one speaks TLS 1.2 and 1.3,
    /// and refuses a range without either; under `-Dimpl=libssl`, AWS-LC
    /// speaks TLS 1.0 to 1.3.
    min_version: ?proto.Version = null,
    max_version: ?proto.Version = null,
    /// Offered in this order. A version is offered only when it is in
    /// range and a suite of it is listed.
    ///
    /// Null is the implementation's default. For the native one, that is
    /// `default_cipher_suites`, with ChaCha20-Poly1305 first on a machine
    /// without AES instructions (`default_cipher_suites_chacha_first`), as
    /// for a list equal to it; it refuses a suite it does not implement.
    /// Under `-Dimpl=libssl` it is AWS-LC's, which includes CBC and RSA
    /// key exchange suites for older servers, and a list may name any
    /// suite AWS-LC knows.
    cipher_suites: ?[]const proto.CipherSuite = null,
    /// In preference order, with at least one group ztls knows. Groups
    /// the implementation has no key exchange for are not offered: the
    /// native one has none for secp521r1, and refuses a list with nothing
    /// else. In TLS 1.2 this also limits the curve of the server's ECDSA
    /// certificate; there a P-521 one is taken when secp521r1 is listed.
    named_groups: []const proto.NamedGroup = &default_named_groups,
    /// Groups to send key shares for; each must be in `named_groups`, and
    /// listed once. The native implementation refuses secp521r1 here too.
    ///
    /// Not used under `-Dimpl=libssl`, where AWS-LC picks the shares: one
    /// for the first of `named_groups`, and one for the first group after
    /// it of the other kind, post-quantum or classical. With the default
    /// `named_groups`, those are the default key shares. The rules above
    /// are checked all the same.
    key_shares: []const proto.NamedGroup = &default_key_shares,
    /// Sent as signature_algorithms, and the only schemes the server may
    /// sign the handshake with: its CertificateVerify, or in TLS 1.2 its
    /// ServerKeyExchange. Signatures inside the certificate chain are
    /// checked by X.509 verification, not against this list, but in TLS
    /// 1.3 the list also tells the server which chain signatures we take:
    /// leaving out rsa_pkcs1_* may make it pick another certificate or
    /// fail. Not empty, and each one of `known_signature_schemes`.
    ///
    /// Null is the implementation's default: `default_signature_schemes`
    /// for the native one, and under `-Dimpl=libssl`
    /// `known_signature_schemes`, which adds TLS 1.2's SHA-1 ones.
    verify_schemes: ?[]const proto.SignatureScheme = null,
    /// What a client certificate's key signs with, in preference order:
    /// the first the server accepts that suits the key. Each must be one
    /// of `known_signature_schemes`. Empty never presents `auth`. Before
    /// TLS 1.2, which has no schemes, any RSA or ECDSA key signs.
    ///
    /// Null is the implementation's default, as for `verify_schemes`.
    signing_schemes: ?[]const proto.SignatureScheme = null,
    /// Offered through ALPN, in preference order. Empty sends no ALPN.
    alpn_protocols: []const []const u8 = &.{},
    /// The time the server's certificate must be valid at. Null reads
    /// the real clock through `io` when the certificate is checked.
    now: ?std.Io.Timestamp = null,
    /// Treat a transport that ends without close_notify as truncated even
    /// between records.
    strict_close_notify: bool = false,
    /// The longest Certificate or CertificateRequest message accepted
    /// from the peer. Other handshake messages are held to 16 KiB, or to
    /// this if it is less.
    ///
    /// Under `-Dimpl=libssl` every handshake message is held to this, but
    /// to no less than 16 KiB.
    max_handshake_message_len: usize = 64 * 1024,
    /// Keep a copy of the server's certificate chain in
    /// `Connection.peer_certificates`, allocated through `gpa`.
    keep_peer_certificates: bool = false,
};

pub const Server = struct {
    /// What the connection waits with: under `-Dimpl=libssl`, the reading
    /// and the writing task take turns at libssl's state under a lock that
    /// parks the waiting task rather than its thread. The native engine
    /// does not use it.
    io: std.Io,
    /// For the handshake's working memory, such as the peer's messages
    /// while they are reassembled. Nothing is kept after the handshake unless
    /// `keep_peer_certificates` is set; then it must stay valid until
    /// `Connection.deinit()`.
    gpa: Allocator,
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
    /// The lowest and highest versions spoken. Null is the
    /// implementation's own bound: the native server speaks TLS 1.3 only,
    /// and refuses a range without it; under `-Dimpl=libssl`, AWS-LC
    /// speaks TLS 1.0 to 1.3.
    min_version: ?proto.Version = null,
    max_version: ?proto.Version = null,
    /// In preference order, followed over the client's. A version is
    /// spoken only when it is in range and a suite of it is listed.
    ///
    /// Null is the implementation's default. Among the TLS 1.3 suites, it
    /// prefers ChaCha20-Poly1305 when either side lacks AES instructions:
    /// this machine, or a client that lists it first; so does a list
    /// equal to `CipherSuite.all`, and any other is followed as given. The
    /// native server skips TLS 1.2 suites, and needs a TLS 1.3 one. Under
    /// `-Dimpl=libssl` the default for older versions is AWS-LC's, and a
    /// list may name any suite AWS-LC knows.
    cipher_suites: ?[]const proto.CipherSuite = null,
    /// In preference order, followed over the client's, with at least one
    /// group ztls knows. Groups the implementation has no key exchange for
    /// are passed over: the native one has none for secp521r1. The native
    /// server takes its favourite of the groups the client sent a key
    /// share for, and asks for another with a HelloRetryRequest only when
    /// it can use none of them. Under `-Dimpl=libssl`, AWS-LC takes its
    /// favourite of all the groups the client supports, asking for that
    /// one's share when it was not sent.
    named_groups: []const proto.NamedGroup = &default_server_named_groups,
    /// Sent in a CertificateRequest, and the only schemes a client
    /// certificate's key may sign with. Signatures inside the chain are
    /// checked by X.509 verification, not against this list, but in TLS
    /// 1.3 the list also tells the client which chain signatures we take.
    /// Not empty, and each one of `known_signature_schemes`.
    ///
    /// Null is the implementation's default: `default_signature_schemes`
    /// for the native one, and under `-Dimpl=libssl`
    /// `known_signature_schemes`, which adds TLS 1.2's SHA-1 ones.
    verify_schemes: ?[]const proto.SignatureScheme = null,
    /// What the server signs with, in preference order: the first the
    /// client accepts that suits the certificate's key. A certificate
    /// with no such scheme is passed over; before TLS 1.2, which has no
    /// schemes, one with a key other than RSA or ECDSA is. Not empty, and
    /// each one of `known_signature_schemes`.
    ///
    /// Null is the implementation's default, as for `verify_schemes`.
    signing_schemes: ?[]const proto.SignatureScheme = null,
    /// Supported, in preference order. A client whose offer shares none
    /// is refused with no_application_protocol; one that offers none
    /// gets none. Empty disables ALPN.
    alpn_protocols: []const []const u8 = &.{},
    /// The time a client certificate must be valid at. Null reads the
    /// real clock through `io` when the certificate is checked.
    now: ?std.Io.Timestamp = null,
    strict_close_notify: bool = false,
    /// The longest client Certificate message accepted. Other handshake
    /// messages, and all of them without `client_auth`, are held to
    /// 16 KiB, or to this if it is less.
    ///
    /// Under `-Dimpl=libssl`, with `client_auth` every handshake message is
    /// held to this, but to no less than 16 KiB; without it, to 16 KiB.
    max_handshake_message_len: usize = 64 * 1024,
    /// Keep a copy of the client's certificate chain, if it sent one, in
    /// `Connection.peer_certificates`, allocated through `gpa`.
    keep_peer_certificates: bool = false,
};

const testing = std.testing;

test "CertKeyPair frees what it has when an allocation fails" {
    const S = struct {
        fn load(allocator: Allocator) !void {
            var pair = try CertKeyPair.fromSlice(allocator, @embedFile("testdata/pki/server-chain.pem"), @embedFile("testdata/pki/server-chain.key"));
            pair.deinit(allocator);
        }
    };
    try testing.checkAllAllocationFailures(testing.allocator, S.load, .{});
}

test "CertKeyPair from the test PKI" {
    var pair = try CertKeyPair.fromSlice(testing.allocator, @embedFile("testdata/pki/server-chain.pem"), @embedFile("testdata/pki/server-chain.key"));
    defer pair.deinit(testing.allocator);
    try testing.expectEqual(2, pair.chain.len); // leaf and intermediate
    try testing.expectEqual(crypto.sig.KeyType{ .ecdsa = .p384 }, pair.key.key_type);
    var leaf = try Certificate.parseDer(pair.chain[0]);
    defer leaf.deinit();
    try testing.expect(leaf.matchesPrivateKey(&pair.key));

    var rsa = try CertKeyPair.fromSlice(testing.allocator, @embedFile("testdata/pki/server-rsa.pem"), @embedFile("testdata/pki/server-rsa.key"));
    defer rsa.deinit(testing.allocator);
    try testing.expectEqual(1, rsa.chain.len);
}

test "CertKeyPair from files" {
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(io, .{ .sub_path = "chain.pem", .data = @embedFile("testdata/pki/server-chain.pem") });
    try tmp.dir.writeFile(io, .{ .sub_path = "key.pem", .data = @embedFile("testdata/pki/server-chain.key") });
    try tmp.dir.writeFile(io, .{ .sub_path = "other.key", .data = @embedFile("testdata/pki/client.key") });

    var pair = try CertKeyPair.fromFilePath(testing.allocator, io, tmp.dir, "chain.pem", "key.pem");
    defer pair.deinit(testing.allocator);
    try testing.expectEqual(2, pair.chain.len);

    try testing.expectError(error.KeyMismatch, CertKeyPair.fromFilePath(testing.allocator, io, tmp.dir, "chain.pem", "other.key"));
    try testing.expectError(error.FileNotFound, CertKeyPair.fromFilePath(testing.allocator, io, tmp.dir, "chain.pem", "missing.key"));
    try testing.expectError(error.FileNotFound, CertKeyPair.fromFilePath(testing.allocator, io, tmp.dir, "missing.pem", "key.pem"));

    // A key file past the first buffer, and one past the limit.
    const padding: [5000]u8 = @splat('\n');
    try tmp.dir.writeFile(io, .{ .sub_path = "padded.key", .data = &padding ++ @embedFile("testdata/pki/server-chain.key") });
    var padded = try CertKeyPair.fromFilePath(testing.allocator, io, tmp.dir, "chain.pem", "padded.key");
    defer padded.deinit(testing.allocator);
    const huge = try testing.allocator.alloc(u8, CertKeyPair.max_file_len + 1);
    defer testing.allocator.free(huge);
    @memset(huge, '\n');
    try tmp.dir.writeFile(io, .{ .sub_path = "huge.key", .data = huge });
    try testing.expectError(error.StreamTooLong, CertKeyPair.fromFilePath(testing.allocator, io, tmp.dir, "chain.pem", "huge.key"));
}

test "CertKeyPair refuses a key that is not the leaf's, and no certificate" {
    try testing.expectError(error.KeyMismatch, CertKeyPair.fromSlice(testing.allocator, @embedFile("testdata/pki/server-ec.pem"), @embedFile("testdata/pki/client.key")));
    try testing.expectError(error.InvalidCertificate, CertKeyPair.fromSlice(testing.allocator, @embedFile("testdata/pki/server-ec.key"), @embedFile("testdata/pki/server-ec.key")));
    try testing.expectError(error.InvalidKey, CertKeyPair.fromSlice(testing.allocator, @embedFile("testdata/pki/server-ec.pem"), @embedFile("testdata/pki/server-ec.pem")));
}
