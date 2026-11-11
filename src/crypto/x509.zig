//! Certificates, the trust store and chain verification through AWS-LC's
//! X.509 code. PEM is decoded here and DER parsed by AWS-LC; files are
//! read through `std.Io`, and only where the application asks for the
//! system's roots.

const std = @import("std");
const builtin = @import("builtin");
const c = @import("c");
const err = @import("err.zig");
const pem = @import("pem.zig");
const sig = @import("sig.zig");
const Bundle = std.crypto.Certificate.Bundle;

const log = std.log.scoped(.ztls);

pub const Certificate = struct {
    x509: *c.X509,

    pub fn parseDer(der: []const u8) error{InvalidCertificate}!Certificate {
        var p: [*c]const u8 = der.ptr;
        const x509 = c.d2i_X509(null, &p, @intCast(der.len)) orelse {
            _ = err.take();
            return error.InvalidCertificate;
        };
        if (p != der.ptr + der.len) {
            c.X509_free(x509);
            return error.InvalidCertificate;
        }
        return .{ .x509 = x509 };
    }

    /// The first CERTIFICATE block in `text`.
    pub fn parsePem(gpa: std.mem.Allocator, text: []const u8) (pem.Error || error{ InvalidCertificate, OutOfMemory })!Certificate {
        var it = pem.Iterator.init(text);
        while (try it.next()) |block| {
            if (!std.mem.eql(u8, block.label, "CERTIFICATE")) continue;
            const buf = try gpa.alloc(u8, block.decodedSizeUpperBound());
            defer gpa.free(buf);
            return parseDer(try block.decode(buf));
        }
        return error.InvalidCertificate;
    }

    pub fn deinit(self: *Certificate) void {
        c.X509_free(self.x509);
        self.* = undefined;
    }

    /// The subject's key, for verifying CertificateVerify. A key AWS-LC
    /// cannot load, such as DSA or one on a curve it lacks, is unsupported.
    pub fn publicKey(self: *const Certificate) error{UnsupportedKey}!sig.PublicKey {
        const pkey = c.X509_get_pubkey(self.x509) orelse {
            _ = err.take();
            return error.UnsupportedKey;
        };
        return sig.PublicKey.fromPkey(pkey);
    }

    /// Whether the key may make signatures: a keyUsage extension, when
    /// present, must have digitalSignature (RFC 5280 §4.2.1.3), and TLS 1.3
    /// authenticates with signatures only.
    pub fn allowsDigitalSignature(self: *const Certificate) bool {
        // Parsing the extensions queues an error for a malformed one.
        defer c.ERR_clear_error();
        // All bits without the extension, none if the extensions are
        // malformed.
        return c.X509_get_key_usage(self.x509) & c.X509v3_KU_DIGITAL_SIGNATURE != 0;
    }

    /// Whether the certificate is for `host`: a DNS subject alternative
    /// name matches it (wildcards included); the subject common name is
    /// never consulted.
    pub fn matchesHost(self: *const Certificate, host: []const u8) bool {
        // A zero length tells AWS-LC to call strlen instead.
        if (host.len == 0) return false;
        const r = c.X509_check_host(self.x509, host.ptr, host.len, c.X509_CHECK_FLAG_NEVER_CHECK_SUBJECT, null);
        if (r == 1) return true;
        _ = err.take();
        return false;
    }

    /// Whether `key` is the private half of the subject's key.
    pub fn matchesPrivateKey(self: *const Certificate, key: *const sig.PrivateKey) bool {
        if (c.X509_check_private_key(self.x509, key.pkey) == 1) return true;
        _ = err.take();
        return false;
    }
};

/// The certificate authorities a peer's chain must lead to. Built by the
/// caller, then shared read-only by any number of connections on any
/// threads; nothing may be added once connections use it.
///
/// Any certificate in the store is a trust anchor: an intermediate stays
/// trusted even when its root is expired or absent, and a leaf in the
/// store pins that leaf.
pub const TrustStore = struct {
    store: *c.X509_STORE,

    pub fn init() err.Error!TrustStore {
        const store = c.X509_STORE_new() orelse return err.fail();
        // Any certificate in the store is a trust anchor, including an
        // intermediate, as Go and std.crypto.Certificate.Bundle have it;
        // otherwise a chain would have to reach a self-signed root.
        if (c.X509_STORE_set_flags(store, c.X509_V_FLAG_PARTIAL_CHAIN) != 1) {
            c.X509_STORE_free(store);
            return err.fail();
        }
        return .{ .store = store };
    }

    pub fn deinit(self: *TrustStore) void {
        c.X509_STORE_free(self.store);
        self.* = undefined;
    }

    pub fn addDer(self: *TrustStore, der: []const u8) error{ InvalidCertificate, CryptoFailed }!void {
        var cert = try Certificate.parseDer(der);
        defer cert.deinit();
        try self.addCertificate(&cert);
    }

    /// Adds a copy of the certificate.
    pub fn addCertificate(self: *TrustStore, cert: *const Certificate) err.Error!void {
        // A duplicate is compared with what the store holds, which parses
        // both certificates' extensions, malformed ones included.
        defer c.ERR_clear_error();
        if (c.X509_STORE_add_cert(self.store, cert.x509) != 1) return err.fail();
    }

    pub const AddPemError = pem.Error || error{ InvalidCertificate, CryptoFailed, OutOfMemory, NoCertificates };

    /// Adds every CERTIFICATE block in `text`; other blocks are ignored.
    /// None at all is `error.NoCertificates`.
    pub fn addPem(self: *TrustStore, gpa: std.mem.Allocator, text: []const u8) AddPemError!void {
        if (try self.addPemBlocks(gpa, text, .fail) == 0) return error.NoCertificates;
    }

    const OnInvalid = enum { fail, skip };

    /// With `.fail`, a malformed block or a certificate AWS-LC does not
    /// parse is an error; with `.skip` it is logged and the rest still
    /// read. Returns how many certificates were accepted.
    fn addPemBlocks(self: *TrustStore, gpa: std.mem.Allocator, text: []const u8, comptime on_invalid: OnInvalid) !usize {
        var accepted: usize = 0;
        var it = pem.Iterator.init(text);
        while (true) {
            const block = (it.next() catch switch (on_invalid) {
                .fail => return error.InvalidPem,
                .skip => {
                    log.debug("skipping a malformed PEM block", .{});
                    continue;
                },
            }) orelse break;
            if (!std.mem.eql(u8, block.label, "CERTIFICATE")) continue;
            const buf = try gpa.alloc(u8, block.decodedSizeUpperBound());
            defer gpa.free(buf);
            const der = block.decode(buf) catch switch (on_invalid) {
                .fail => return error.InvalidPem,
                .skip => {
                    log.debug("skipping a PEM block that is not base64", .{});
                    continue;
                },
            };
            self.addDer(der) catch |e| switch (e) {
                error.InvalidCertificate => switch (on_invalid) {
                    .fail => return error.InvalidCertificate,
                    .skip => {
                        log.debug("skipping a certificate that AWS-LC does not parse", .{});
                        continue;
                    },
                },
                error.CryptoFailed => return error.CryptoFailed,
            };
            accepted += 1;
        }
        return accepted;
    }

    /// How many certificates the store holds. For while the store is being
    /// built: it reads the store without its lock, so not on one already
    /// shared with connections that verify against it.
    pub fn count(self: *const TrustStore) usize {
        return c.sk_X509_OBJECT_num(c.X509_STORE_get0_objects(self.store));
    }

    pub const AddPemFileError = std.Io.Dir.ReadFileAllocError || AddPemError;

    /// Adds the certificates in the PEM file at `sub_path` under `dir`. A
    /// file the caller named is taken at its word: a malformed block or a
    /// certificate AWS-LC does not parse is an error, and a file with no
    /// certificate is `error.NoCertificates`.
    pub fn addPemFile(self: *TrustStore, gpa: std.mem.Allocator, io: std.Io, dir: std.Io.Dir, sub_path: []const u8) AddPemFileError!void {
        const text = try dir.readFileAlloc(io, sub_path, gpa, .limited(max_pem_file_len));
        defer gpa.free(text);
        if (try self.addPemBlocks(gpa, text, .fail) == 0) return error.NoCertificates;
    }

    pub const AddPemDirError = std.Io.Dir.Iterator.Error || std.Io.Dir.ReadFileAllocError || AddPemError;

    /// Adds the certificates in every file of `dir`, as a directory of
    /// single roots is laid out. A link to nothing or to a directory, or
    /// a file with no PEM in it, is passed over; a file that cannot be
    /// read, or has a malformed block, is an error, as with `addPemFile`.
    /// No certificate in the whole directory is `error.NoCertificates`.
    pub fn addPemDir(self: *TrustStore, gpa: std.mem.Allocator, io: std.Io, dir: std.Io.Dir) AddPemDirError!void {
        var accepted: usize = 0;
        var it = dir.iterate();
        while (try it.next(io)) |entry| {
            switch (entry.kind) {
                // Some filesystems do not say what an entry is; opening
                // it does.
                .file, .sym_link, .unknown => {},
                else => continue,
            }
            const text = dir.readFileAlloc(io, entry.name, gpa, .limited(max_pem_file_len)) catch |e| switch (e) {
                error.FileNotFound, error.IsDir => {
                    log.debug("skipping {s}: {s}", .{ entry.name, @errorName(e) });
                    continue;
                },
                else => |other| return other,
            };
            defer gpa.free(text);
            accepted += try self.addPemBlocks(gpa, text, .fail);
        }
        if (accepted == 0) return error.NoCertificates;
    }

    /// `addPemFile` for roots the system was found to have: nothing in
    /// the file is taken as a reason to fail the rest. Returns how many
    /// certificates were accepted.
    fn addSystemPemFile(self: *TrustStore, gpa: std.mem.Allocator, io: std.Io, dir: std.Io.Dir, sub_path: []const u8) !usize {
        const text = try dir.readFileAlloc(io, sub_path, gpa, .limited(max_pem_file_len));
        defer gpa.free(text);
        return self.addPemBlocks(gpa, text, .skip);
    }

    /// `addPemDir` for a system directory: one bad entry must not cost
    /// the others, so only running out of memory, cancellation and
    /// AWS-LC failures stop the walk. Returns how many certificates were
    /// accepted.
    fn addSystemPemDir(self: *TrustStore, gpa: std.mem.Allocator, io: std.Io, dir: std.Io.Dir) !usize {
        var accepted: usize = 0;
        var it = dir.iterate();
        while (try it.next(io)) |entry| {
            switch (entry.kind) {
                .file, .sym_link, .unknown => {},
                else => continue,
            }
            accepted += self.addSystemPemFile(gpa, io, dir, entry.name) catch |e| switch (e) {
                error.OutOfMemory => return error.OutOfMemory,
                error.Canceled => return error.Canceled,
                error.CryptoFailed => return error.CryptoFailed,
                else => {
                    log.debug("skipping {s}: {s}", .{ entry.name, @errorName(e) });
                    continue;
                },
            };
        }
        return accepted;
    }

    /// Adds every certificate in `bundle`. One AWS-LC will not parse is
    /// skipped and logged; none left is `error.NoCertificates`.
    ///
    /// Two things about `Bundle` carry over. It keeps one certificate per
    /// subject name, so of two roots with the same name and different keys
    /// only the first read survives. And it parses with std's X.509 code
    /// first: a root with an extension or key type std does not know is
    /// dropped before it gets here, and a malformed one fails the whole
    /// load. For roots that come from the usual CA bundles neither
    /// matters in practice.
    pub fn addBundle(self: *TrustStore, bundle: *const Bundle) (err.Error || error{NoCertificates})!void {
        if (try self.addBundleCounted(bundle) == 0) return error.NoCertificates;
    }

    fn addBundleCounted(self: *TrustStore, bundle: *const Bundle) err.Error!usize {
        var accepted: usize = 0;
        var it = bundle.map.valueIterator();
        while (it.next()) |start| {
            // Each entry is the offset of a DER certificate in `bytes`; its
            // length is in its own header, which Bundle has already parsed.
            const element = std.crypto.Certificate.der.Element.parse(bundle.bytes.items, start.*) catch unreachable;
            const der = bundle.bytes.items[start.*..element.slice.end];
            var cert = Certificate.parseDer(der) catch {
                log.debug("skipping a root certificate at bundle offset {d} that AWS-LC does not parse", .{start.*});
                continue;
            };
            defer cert.deinit();
            try self.addCertificate(&cert);
            accepted += 1;
        }
        return accepted;
    }

    pub const AddSystemBundleError = Bundle.RescanError || std.Io.Dir.Iterator.Error || error{ OutOfMemory, Canceled, CryptoFailed, NoSystemRoots };

    /// Adds the roots the system trusts. On Linux and the other Unixes
    /// they are PEM files at well-known paths (`system_roots`), read here
    /// and given to AWS-LC as they are. On Windows and macOS they live in
    /// a system store that `std.crypto.Certificate.Bundle` knows how to
    /// read, so it does the loading there, with the limitations noted on
    /// `addBundle`. Unlike a file or directory the caller names, what the
    /// system has is taken as found: a root that will not parse, or a
    /// file that cannot be read, is skipped and logged rather than
    /// failing the rest. Finding none at all is `error.NoSystemRoots`,
    /// since a store that trusts nothing is never what was meant.
    pub fn addSystemBundle(self: *TrustStore, gpa: std.mem.Allocator, io: std.Io) AddSystemBundleError!void {
        const added = if (system_roots) |roots|
            try self.addSystemRoots(gpa, io, roots)
        else
            try self.addStdSystemBundle(gpa, io);
        if (added == 0) return error.NoSystemRoots;
    }

    fn addStdSystemBundle(self: *TrustStore, gpa: std.mem.Allocator, io: std.Io) AddSystemBundleError!usize {
        var bundle: Bundle = .empty;
        defer bundle.deinit(gpa);
        try bundle.rescan(gpa, io, std.Io.Clock.real.now(io));
        return self.addBundleCounted(&bundle);
    }

    /// The first bundle file with anything in it wins; an empty or
    /// truncated one, as during a package upgrade, is passed over for the
    /// next, and the directories are tried when no file had roots.
    fn addSystemRoots(self: *TrustStore, gpa: std.mem.Allocator, io: std.Io, roots: SystemRoots) AddSystemBundleError!usize {
        for (roots.files) |path| {
            const added = self.addSystemPemFile(gpa, io, .cwd(), path) catch |e| switch (e) {
                error.OutOfMemory => return error.OutOfMemory,
                error.Canceled => return error.Canceled,
                error.CryptoFailed => return error.CryptoFailed,
                error.FileNotFound => continue,
                else => {
                    log.warn("skipping the system roots in {s}: {s}", .{ path, @errorName(e) });
                    continue;
                },
            };
            if (added > 0) return added;
        }
        var added: usize = 0;
        for (roots.dirs) |path| {
            var dir = std.Io.Dir.openDirAbsolute(io, path, .{ .iterate = true }) catch |e| switch (e) {
                error.Canceled => return error.Canceled,
                error.FileNotFound, error.NotDir => continue,
                else => {
                    log.warn("skipping the system roots in {s}: {s}", .{ path, @errorName(e) });
                    continue;
                },
            };
            defer dir.close(io);
            added += try self.addSystemPemDir(gpa, io, dir);
        }
        return added;
    }
};

/// The most a PEM file read for roots may be. Distribution bundles are a
/// few hundred KiB.
const max_pem_file_len = 16 << 20;

/// Where a Unix system keeps the roots it trusts: bundle files, of which
/// the first one found is read, and failing that directories of single
/// certificates, all of which are. The same places std looks.
const SystemRoots = struct {
    files: []const []const u8,
    dirs: []const []const u8 = &.{},
};

const system_roots: ?SystemRoots = switch (builtin.os.tag) {
    .linux => .{
        .files = &.{
            "/etc/ssl/certs/ca-certificates.crt", // Debian, Ubuntu, Arch, Gentoo
            "/etc/pki/tls/certs/ca-bundle.crt", // Fedora, RHEL 6
            "/etc/ssl/ca-bundle.pem", // OpenSUSE
            "/etc/pki/tls/cacert.pem", // OpenELEC
            "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem", // CentOS, RHEL 7
            "/etc/ssl/cert.pem", // Alpine
        },
        .dirs = &.{
            "/etc/ssl/certs", // SLES
            "/etc/pki/tls/certs", // Fedora, RHEL
            "/system/etc/security/cacerts", // Android
        },
    },
    .freebsd, .openbsd => .{ .files = &.{"/etc/ssl/cert.pem"} },
    .netbsd => .{ .files = &.{"/etc/openssl/certs/ca-certificates.crt"} },
    .dragonfly => .{ .files = &.{"/usr/local/etc/ssl/cert.pem"} },
    .illumos => .{ .files = &.{"/etc/ssl/cacert.pem"} },
    .haiku => .{ .files = &.{"/boot/system/data/ssl/CARootCertificates.pem"} },
    .serenity => .{ .files = &.{"/etc/ssl/certs/ca-certificates.crt"} },
    // Windows and macOS keep their roots in a system store.
    else => null,
};

pub const Purpose = enum {
    /// The peer is a TLS server: id-kp-serverAuth.
    server,
    /// The peer is a TLS client: id-kp-clientAuth.
    client,
};

pub const VerifyOptions = struct {
    /// The time to validate at, in seconds since the Unix epoch.
    now: i64,
    purpose: Purpose,
    /// Checked against the leaf's DNS subject alternative names; the
    /// subject common name is never used.
    host: ?[]const u8 = null,
    /// A 4- or 16-byte address, checked against the leaf's IP subject
    /// alternative names.
    ip: ?[]const u8 = null,
};

/// Each name is a TLS alert, or the closest one.
pub const VerifyError = error{
    CertificateExpired,
    CertificateNotYetValid,
    /// The chain does not lead to a certificate in the store.
    UnknownCa,
    /// The leaf does not name the host or address.
    HostnameMismatch,
    /// Anything else: a bad signature, a broken chain, the wrong purpose.
    BadCertificate,
    CryptoFailed,
};

/// Verifies `chain`, leaf first, against the store. The rest of the chain
/// is untrusted: it only helps build a path to a trusted root.
pub fn verify(store: *const TrustStore, chain: []const Certificate, options: VerifyOptions) VerifyError!void {
    std.debug.assert(chain.len > 0);
    // On success too: AWS-LC may queue errors it got past.
    defer c.ERR_clear_error();
    const ctx = c.X509_STORE_CTX_new() orelse return err.fail();
    defer c.X509_STORE_CTX_free(ctx);

    const untrusted = c.sk_X509_new_null() orelse return err.fail();
    defer c.sk_X509_free(untrusted); // holds no references of its own
    for (chain[1..]) |cert| {
        if (c.sk_X509_push(untrusted, cert.x509) == 0) return err.fail();
    }

    if (c.X509_STORE_CTX_init(ctx, store.store, chain[0].x509, untrusted) != 1) return err.fail();
    const param = c.X509_STORE_CTX_get0_param(ctx);
    c.X509_VERIFY_PARAM_set_time_posix(param, options.now);
    const purpose: c_int = switch (options.purpose) {
        .server => c.X509_PURPOSE_SSL_SERVER,
        .client => c.X509_PURPOSE_SSL_CLIENT,
    };
    if (c.X509_STORE_CTX_set_purpose(ctx, purpose) != 1) return err.fail();
    if (options.host) |host| {
        // A zero length tells AWS-LC to call strlen and then, finding
        // nothing, to check no name at all.
        std.debug.assert(host.len != 0);
        c.X509_VERIFY_PARAM_set_hostflags(param, c.X509_CHECK_FLAG_NEVER_CHECK_SUBJECT);
        if (c.X509_VERIFY_PARAM_set1_host(param, host.ptr, host.len) != 1) return err.fail();
    }
    if (options.ip) |ip| {
        if (c.X509_VERIFY_PARAM_set1_ip(param, ip.ptr, ip.len) != 1) return err.fail();
    }

    if (c.X509_verify_cert(ctx) == 1) return checkSignatureDigests(ctx);
    const code = c.X509_STORE_CTX_get_error(ctx);
    _ = err.take();
    return switch (code) {
        c.X509_V_ERR_CERT_HAS_EXPIRED => error.CertificateExpired,
        c.X509_V_ERR_CERT_NOT_YET_VALID => error.CertificateNotYetValid,
        c.X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT,
        c.X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY,
        c.X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE,
        c.X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT,
        c.X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN,
        c.X509_V_ERR_CERT_UNTRUSTED,
        => error.UnknownCa,
        c.X509_V_ERR_HOSTNAME_MISMATCH, c.X509_V_ERR_IP_ADDRESS_MISMATCH => error.HostnameMismatch,
        else => {
            if (std.log.logEnabled(.debug, .ztls)) {
                var subject: [256]u8 = undefined;
                const name = c.X509_NAME_oneline(c.X509_get_subject_name(c.X509_STORE_CTX_get_current_cert(ctx)), &subject, subject.len);
                log.debug("certificate verification failed at depth {d} ({s}): {s}", .{
                    c.X509_STORE_CTX_get_error_depth(ctx),
                    if (name) |n| std.mem.sliceTo(n, 0) else "?",
                    c.X509_verify_cert_error_string(code),
                });
            }
            return error.BadCertificate;
        },
    };
}

/// AWS-LC refuses MD4 and MD5 signatures in a chain; SHA-1 is refused
/// here. AWS-LC has checked the signature of every certificate on the
/// path it built but the last, usually the trust anchor.
fn checkSignatureDigests(ctx: *c.X509_STORE_CTX) VerifyError!void {
    const path = c.X509_STORE_CTX_get0_chain(ctx);
    const n: usize = c.sk_X509_num(path);
    for (0..n -| 1) |i| {
        if (signatureDigest(c.sk_X509_value(path, i).?) == c.NID_sha1) {
            log.debug("certificate verification failed at depth {d}: signed with SHA-1", .{i});
            return error.BadCertificate;
        }
    }
}

/// The hash a certificate was signed with, or `NID_undef` for a signature
/// algorithm that has none of its own, such as Ed25519.
fn signatureDigest(cert: *const c.X509) c_int {
    const nid = c.X509_get_signature_nid(cert);
    if (nid == c.NID_rsassaPss) return pssDigest(cert);
    var digest: c_int = c.NID_undef;
    if (c.OBJ_find_sigid_algs(nid, &digest, null) != 1) return c.NID_undef;
    return digest;
}

/// RSASSA-PSS names its hash in its parameters, and SHA-1 by naming none
/// (RFC 4055 §3.1). Parameters that do not parse count as SHA-1; AWS-LC
/// would not have verified with them anyway.
fn pssDigest(cert: *const c.X509) c_int {
    var alg: ?*const c.X509_ALGOR = null;
    c.X509_get0_signature(null, &alg, cert);
    var param_type: c_int = c.V_ASN1_UNDEF;
    var param: ?*const anyopaque = null;
    c.X509_ALGOR_get0(null, &param_type, &param, alg);
    if (param_type != c.V_ASN1_SEQUENCE) return c.NID_sha1;
    const sequence: *const c.ASN1_STRING = @ptrCast(@alignCast(param.?));
    var der: [*c]const u8 = c.ASN1_STRING_get0_data(sequence);
    const params = c.d2i_RSA_PSS_PARAMS(null, &der, c.ASN1_STRING_length(sequence)) orelse {
        _ = err.take();
        return c.NID_sha1;
    };
    defer c.RSA_PSS_PARAMS_free(params);
    const hash = params.*.hashAlgorithm orelse return c.NID_sha1;
    var obj: ?*const c.ASN1_OBJECT = null;
    c.X509_ALGOR_get0(&obj, null, null, hash);
    return c.OBJ_obj2nid(obj);
}

const testing = std.testing;

const pki = struct {
    const ca = @embedFile("../testdata/pki/ca.pem");
    const intermediate = @embedFile("../testdata/pki/intermediate.pem");
    const server_ec = @embedFile("../testdata/pki/server-ec.pem");
    const server_ec_key = @embedFile("../testdata/pki/server-ec.key");
    const server_rsa = @embedFile("../testdata/pki/server-rsa.pem");
    const server_ed25519 = @embedFile("../testdata/pki/server-ed25519.pem");
    const server_chain = @embedFile("../testdata/pki/server-chain.pem");
    const client = @embedFile("../testdata/pki/client.pem");
    const client_key = @embedFile("../testdata/pki/client.key");
    const selfsigned = @embedFile("../testdata/pki/selfsigned.pem");
    const server_sha1 = @embedFile("../testdata/pki/server-sha1.pem");
    const ca_sha1 = @embedFile("../testdata/pki/ca-sha1.pem");
    const intermediate_sha1 = @embedFile("../testdata/pki/intermediate-sha1.pem");
    const ca_rsa = @embedFile("../testdata/pki/ca-rsa.pem");
    const server_pss_sha1 = @embedFile("../testdata/pki/server-pss-sha1.pem");
    const server_pss_sha256 = @embedFile("../testdata/pki/server-pss-sha256.pem");
};

/// Within the test PKI's validity (2027-01-15).
const valid_now: i64 = 1_800_000_000;

fn trustTestCa() !TrustStore {
    var store = try TrustStore.init();
    errdefer store.deinit();
    try store.addPem(testing.allocator, pki.ca);
    return store;
}

test "server certificates verify for their names" {
    var store = try trustTestCa();
    defer store.deinit();
    for ([_][]const u8{ pki.server_ec, pki.server_rsa, pki.server_ed25519 }) |text| {
        var cert = try Certificate.parsePem(testing.allocator, text);
        defer cert.deinit();
        const chain = [_]Certificate{cert};
        try verify(&store, &chain, .{ .now = valid_now, .purpose = .server, .host = "localhost" });
        try verify(&store, &chain, .{ .now = valid_now, .purpose = .server, .host = "LOCALHOST" });
        try verify(&store, &chain, .{ .now = valid_now, .purpose = .server, .host = "www.example.test" });
        try verify(&store, &chain, .{ .now = valid_now, .purpose = .server, .ip = &.{ 127, 0, 0, 1 } });
        var loopback6: [16]u8 = @splat(0);
        loopback6[15] = 1;
        try verify(&store, &chain, .{ .now = valid_now, .purpose = .server, .ip = &loopback6 });
        try verify(&store, &chain, .{ .now = valid_now, .purpose = .server });

        try testing.expectError(error.HostnameMismatch, verify(&store, &chain, .{ .now = valid_now, .purpose = .server, .host = "example.test" }));
        try testing.expectError(error.HostnameMismatch, verify(&store, &chain, .{ .now = valid_now, .purpose = .server, .host = "a.b.example.test" }));
        try testing.expectError(error.HostnameMismatch, verify(&store, &chain, .{ .now = valid_now, .purpose = .server, .host = "localhost.example.com" }));
        try testing.expectError(error.HostnameMismatch, verify(&store, &chain, .{ .now = valid_now, .purpose = .server, .ip = &.{ 10, 0, 0, 1 } }));
        try testing.expectError(error.CertificateNotYetValid, verify(&store, &chain, .{ .now = 1_000_000_000, .purpose = .server, .host = "localhost" }));
        try testing.expectError(error.CertificateExpired, verify(&store, &chain, .{ .now = 7_000_000_000, .purpose = .server, .host = "localhost" }));
        try testing.expectError(error.BadCertificate, verify(&store, &chain, .{ .now = valid_now, .purpose = .client }));
    }
}

test "a chain through an intermediate" {
    var store = try trustTestCa();
    defer store.deinit();
    // server-chain.pem holds the leaf and then the intermediate.
    var it = pem.Iterator.init(pki.server_chain);
    var chain: [2]Certificate = undefined;
    for (&chain) |*cert| {
        const block = (try it.next()).?;
        var buf: [2048]u8 = undefined;
        cert.* = try Certificate.parseDer(try block.decode(&buf));
    }
    defer for (&chain) |*cert| cert.deinit();

    try verify(&store, &chain, .{ .now = valid_now, .purpose = .server, .host = "localhost" });
    try testing.expectError(error.UnknownCa, verify(&store, chain[0..1], .{ .now = valid_now, .purpose = .server, .host = "localhost" }));

    // With the intermediate itself trusted, the leaf alone is enough.
    var store2 = try TrustStore.init();
    defer store2.deinit();
    try store2.addPem(testing.allocator, pki.intermediate);
    try verify(&store2, chain[0..1], .{ .now = valid_now, .purpose = .server, .host = "localhost" });
}

test "a std.crypto.Certificate.Bundle as the source of roots" {
    var bundle: Bundle = .empty;
    defer bundle.deinit(testing.allocator);
    for ([_][]const u8{ pki.ca, pki.intermediate }) |text| {
        var it = pem.Iterator.init(text);
        const block = (try it.next()).?;
        const start: u32 = @intCast(bundle.bytes.items.len);
        const dest = try bundle.bytes.addManyAsSlice(testing.allocator, block.decodedSizeUpperBound());
        bundle.bytes.items.len = start + (try block.decode(dest)).len;
        try bundle.parseCert(testing.allocator, start, valid_now);
    }
    try testing.expectEqual(2, bundle.map.count());

    var store = try TrustStore.init();
    defer store.deinit();
    try store.addBundle(&bundle);
    try testing.expectEqual(2, store.count());

    var cert = try Certificate.parsePem(testing.allocator, pki.server_ec);
    defer cert.deinit();
    try verify(&store, &.{cert}, .{ .now = valid_now, .purpose = .server, .host = "localhost" });
}

test "roots from PEM files and a directory of them" {
    const io = testing.io;
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    // A directory of roots: certificates, a key, a note, and the links a
    // distribution leaves beside them.
    try tmp.dir.createDirPath(io, "certs/empty");
    try tmp.dir.writeFile(io, .{ .sub_path = "certs/ca.pem", .data = pki.ca });
    try tmp.dir.writeFile(io, .{ .sub_path = "certs/intermediate.pem", .data = pki.intermediate });
    try tmp.dir.writeFile(io, .{ .sub_path = "certs/key.pem", .data = pki.server_ec_key });
    try tmp.dir.writeFile(io, .{ .sub_path = "certs/README", .data = "Not a certificate.\n" });
    // Windows needs a privilege for symlinks; the test stands without them.
    if (builtin.os.tag != .windows) {
        try tmp.dir.symLink(io, "empty", "certs/link-to-dir", .{});
        try tmp.dir.symLink(io, "gone.pem", "certs/dangling.pem", .{});
        try tmp.dir.symLink(io, "ca.pem", "certs/abcd1234.0", .{}); // a hashed name for the same root
    }
    // Damaged files: a block that is not base64, and a bundle with a paste
    // error between two good certificates.
    try tmp.dir.writeFile(io, .{ .sub_path = "broken.pem", .data = "-----BEGIN CERTIFICATE-----\n!!!\n-----END CERTIFICATE-----\n" });
    try tmp.dir.writeFile(io, .{ .sub_path = "bundle.crt", .data = pki.ca ++ "-----BEGIN CERTIFICATE-----\n!!!\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\nunterminated\n" ++ pki.intermediate });

    var certs = try tmp.dir.openDir(io, "certs", .{ .iterate = true });
    defer certs.close(io);

    // A file the caller names is taken at its word.
    var store = try TrustStore.init();
    defer store.deinit();
    try store.addPemFile(testing.allocator, io, certs, "ca.pem");
    try store.addPemFile(testing.allocator, io, certs, "ca.pem"); // already held, still a certificate
    try testing.expectEqual(1, store.count());
    try testing.expectError(error.NoCertificates, store.addPemFile(testing.allocator, io, certs, "key.pem"));
    try testing.expectError(error.NoCertificates, store.addPem(testing.allocator, pki.server_ec_key));
    try testing.expectError(error.FileNotFound, store.addPemFile(testing.allocator, io, certs, "missing.pem"));
    try testing.expectError(error.InvalidPem, store.addPemFile(testing.allocator, io, tmp.dir, "broken.pem"));
    try testing.expectError(error.InvalidPem, store.addPemFile(testing.allocator, io, tmp.dir, "bundle.crt"));
    try testing.expectEqual(1, store.count());

    // A directory the caller names: files without PEM are passed over, a
    // damaged one is not.
    var from_dir = try TrustStore.init();
    defer from_dir.deinit();
    try from_dir.addPemDir(testing.allocator, io, certs);
    try testing.expectEqual(2, from_dir.count());
    var empty = try certs.openDir(io, "empty", .{ .iterate = true });
    defer empty.close(io);
    try testing.expectError(error.NoCertificates, from_dir.addPemDir(testing.allocator, io, empty));
    try testing.expectError(error.InvalidPem, from_dir.addPemDir(testing.allocator, io, tmp.dir));
    // A file the directory holds but we may not read is not passed over.
    if (builtin.os.tag != .windows) {
        try tmp.dir.createDirPath(io, "locked");
        try tmp.dir.writeFile(io, .{ .sub_path = "locked/ca.pem", .data = pki.ca });
        const locked = try tmp.dir.openFile(io, "locked/ca.pem", .{});
        defer locked.close(io);
        try locked.setPermissions(io, .fromMode(0));
        defer locked.setPermissions(io, .fromMode(0o644)) catch {};
        var locked_dir = try tmp.dir.openDir(io, "locked", .{ .iterate = true });
        defer locked_dir.close(io);
        // Root reads anything; then there is nothing to check.
        if (tmp.dir.openFile(io, "locked/ca.pem", .{})) |readable| {
            readable.close(io);
        } else |_| {
            try testing.expectError(error.AccessDenied, from_dir.addPemDir(testing.allocator, io, locked_dir));
        }
    }

    // What the system has is taken as found: the good blocks still count.
    var system = try TrustStore.init();
    defer system.deinit();
    try testing.expectEqual(2, try system.addSystemPemFile(testing.allocator, io, tmp.dir, "bundle.crt"));
    try testing.expectEqual(2, system.count());
    try testing.expectEqual(0, try system.addSystemPemFile(testing.allocator, io, tmp.dir, "broken.pem"));
    var system_dir = try TrustStore.init();
    defer system_dir.deinit();
    try testing.expectEqual(2, try system_dir.addSystemPemDir(testing.allocator, io, tmp.dir));
    try testing.expectEqual(2, system_dir.count());

    var cert = try Certificate.parsePem(testing.allocator, pki.server_ec);
    defer cert.deinit();
    try verify(&from_dir, &.{cert}, .{ .now = valid_now, .purpose = .server, .host = "localhost" });
    try verify(&system_dir, &.{cert}, .{ .now = valid_now, .purpose = .server, .host = "localhost" });
}

test "the system's roots" {
    var store = try TrustStore.init();
    defer store.deinit();
    store.addSystemBundle(testing.allocator, testing.io) catch |e| switch (e) {
        error.FileNotFound => return error.SkipZigTest,
        else => return e,
    };
    // A system has a hundred or so roots, and AWS-LC accepts all that
    // std does; much fewer would mean part of the bundle went unread.
    try testing.expect(store.count() > 50);
}

test "SHA-1 signatures are refused, except on the trust anchor" {
    var store = try trustTestCa();
    defer store.deinit();
    var sha1_leaf = try Certificate.parsePem(testing.allocator, pki.server_sha1);
    defer sha1_leaf.deinit();
    try testing.expectEqual(c.NID_sha1, signatureDigest(sha1_leaf.x509));
    try testing.expectError(error.BadCertificate, verify(&store, &.{sha1_leaf}, .{ .now = valid_now, .purpose = .server, .host = "localhost" }));

    // The intermediate of "a chain through an intermediate", re-signed with
    // SHA-1: refused below the root, fine as the trust anchor itself.
    var chain_leaf = try Certificate.parsePem(testing.allocator, pki.server_chain);
    defer chain_leaf.deinit();
    var sha1_intermediate = try Certificate.parsePem(testing.allocator, pki.intermediate_sha1);
    defer sha1_intermediate.deinit();
    try testing.expectEqual(c.NID_sha1, signatureDigest(sha1_intermediate.x509));
    try testing.expectError(error.BadCertificate, verify(&store, &.{ chain_leaf, sha1_intermediate }, .{ .now = valid_now, .purpose = .server, .host = "localhost" }));
    var sha1_anchor = try TrustStore.init();
    defer sha1_anchor.deinit();
    try sha1_anchor.addPem(testing.allocator, pki.intermediate_sha1);
    try verify(&sha1_anchor, &.{chain_leaf}, .{ .now = valid_now, .purpose = .server, .host = "localhost" });

    // The same CA, self-signed with SHA-1.
    var sha1_root = try TrustStore.init();
    defer sha1_root.deinit();
    try sha1_root.addPem(testing.allocator, pki.ca_sha1);
    var leaf = try Certificate.parsePem(testing.allocator, pki.server_ec);
    defer leaf.deinit();
    try verify(&sha1_root, &.{leaf}, .{ .now = valid_now, .purpose = .server, .host = "localhost" });

    // RSASSA-PSS names its hash in its parameters.
    var rsa_ca = try TrustStore.init();
    defer rsa_ca.deinit();
    try rsa_ca.addPem(testing.allocator, pki.ca_rsa);
    var pss_sha1 = try Certificate.parsePem(testing.allocator, pki.server_pss_sha1);
    defer pss_sha1.deinit();
    try testing.expectEqual(c.NID_sha1, signatureDigest(pss_sha1.x509));
    try testing.expectError(error.BadCertificate, verify(&rsa_ca, &.{pss_sha1}, .{ .now = valid_now, .purpose = .server, .host = "localhost" }));
    var pss_sha256 = try Certificate.parsePem(testing.allocator, pki.server_pss_sha256);
    defer pss_sha256.deinit();
    try testing.expectEqual(c.NID_sha256, signatureDigest(pss_sha256.x509));
    try verify(&rsa_ca, &.{pss_sha256}, .{ .now = valid_now, .purpose = .server, .host = "localhost" });
}

test "untrusted and client certificates" {
    var store = try trustTestCa();
    defer store.deinit();

    var selfsigned = try Certificate.parsePem(testing.allocator, pki.selfsigned);
    defer selfsigned.deinit();
    try testing.expectError(error.UnknownCa, verify(&store, &.{selfsigned}, .{ .now = valid_now, .purpose = .server, .host = "localhost" }));

    var client = try Certificate.parsePem(testing.allocator, pki.client);
    defer client.deinit();
    try verify(&store, &.{client}, .{ .now = valid_now, .purpose = .client });
    try testing.expectError(error.BadCertificate, verify(&store, &.{client}, .{ .now = valid_now, .purpose = .server }));

    var empty = try TrustStore.init();
    defer empty.deinit();
    try testing.expectError(error.UnknownCa, verify(&empty, &.{client}, .{ .now = valid_now, .purpose = .client }));
}

test "public key and private key matching" {
    var cert = try Certificate.parsePem(testing.allocator, pki.server_ec);
    defer cert.deinit();
    var key = try sig.PrivateKey.parsePem(testing.allocator, pki.server_ec_key);
    defer key.deinit();
    var other = try sig.PrivateKey.parsePem(testing.allocator, pki.client_key);
    defer other.deinit();
    try testing.expect(cert.matchesPrivateKey(&key));
    try testing.expect(!cert.matchesPrivateKey(&other));

    var public = try cert.publicKey();
    defer public.deinit();
    try testing.expectEqual(sig.KeyType{ .ecdsa = .p256 }, public.key_type);
    var sig_buf: [128]u8 = undefined;
    const signature = try key.sign(.ecdsa_sha256, "transcript", &sig_buf);
    try public.verify(.ecdsa_sha256, "transcript", signature);
    try testing.expectError(error.SignatureInvalid, public.verify(.ecdsa_sha256, "other", signature));
}

test "matching a certificate's names" {
    var cert = try Certificate.parsePem(testing.allocator, pki.server_ec);
    defer cert.deinit();
    try testing.expect(cert.matchesHost("localhost"));
    try testing.expect(cert.matchesHost("www.example.test"));
    try testing.expect(!cert.matchesHost("example.test"));
    try testing.expect(!cert.matchesHost("localhost.example.com"));
    try testing.expect(!cert.matchesHost(""));
}

test "the error queue is left empty" {
    var store = try trustTestCa();
    defer store.deinit();
    var cert = try Certificate.parsePem(testing.allocator, pki.server_ec);
    defer cert.deinit();
    try verify(&store, &.{cert}, .{ .now = valid_now, .purpose = .server, .host = "localhost" });
    try testing.expectEqual(0, c.ERR_peek_error());

    var buf: [2048]u8 = undefined;
    var bad = try malformedKeyUsage(pki.server_ec, &buf);
    defer bad.deinit();
    try testing.expect(!bad.allowsDigitalSignature());
    try testing.expectEqual(0, c.ERR_peek_error());

    // A second CA under the same subject is compared with the first.
    var bad_ca = try malformedKeyUsage(pki.ca, &buf);
    defer bad_ca.deinit();
    try store.addCertificate(&bad_ca);
    try testing.expectEqual(0, c.ERR_peek_error());
}

/// The certificate in `text` with its keyUsage BIT STRING claiming nine
/// unused bits.
fn malformedKeyUsage(text: []const u8, buf: []u8) !Certificate {
    var it = pem.Iterator.init(text);
    const der = try (try it.next()).?.decode(buf);
    const oid = std.mem.indexOf(u8, der, &.{ 0x06, 0x03, 0x55, 0x1d, 0x0f }).?;
    const bits = oid + std.mem.indexOf(u8, der[oid..], &.{ 0x03, 0x02 }).?;
    der[bits + 2] = 9;
    return Certificate.parseDer(der);
}

test "a key on a curve AWS-LC lacks is unsupported" {
    var it = pem.Iterator.init(pki.server_ec);
    var buf: [2048]u8 = undefined;
    const der = try (try it.next()).?.decode(&buf);
    // prime256v1, 1.2.840.10045.3.1.7, becomes 3.1.8, which names none.
    const at = std.mem.indexOf(u8, der, &.{ 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07 }).?;
    der[at + 9] = 8;
    var cert = try Certificate.parseDer(der);
    defer cert.deinit();
    try testing.expectError(error.UnsupportedKey, cert.publicKey());
    try testing.expectEqual(0, c.ERR_peek_error());
}

test "malformed certificates" {
    try testing.expectError(error.InvalidCertificate, Certificate.parseDer("not der"));
    try testing.expectError(error.InvalidCertificate, Certificate.parsePem(testing.allocator, pki.server_ec_key));
    var it = pem.Iterator.init(pki.ca);
    var buf: [2048]u8 = undefined;
    const der = try (try it.next()).?.decode(&buf);
    try testing.expectError(error.InvalidCertificate, Certificate.parseDer(der[0 .. der.len - 1]));
    buf[der.len] = 0;
    try testing.expectError(error.InvalidCertificate, Certificate.parseDer(buf[0 .. der.len + 1]));
}
