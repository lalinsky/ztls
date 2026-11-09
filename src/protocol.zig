//! The constants of RFC 9846 and friends, and the alerts with their
//! mapping to and from Zig errors.

const std = @import("std");

pub const Version = enum(u16) {
    tls_1_2 = 0x0303,
    tls_1_3 = 0x0304,
    _,
};

pub const ContentType = enum(u8) {
    invalid = 0,
    change_cipher_spec = 20,
    alert = 21,
    handshake = 22,
    application_data = 23,
    _,
};

pub const HandshakeType = enum(u8) {
    hello_request = 0, // TLS 1.2
    client_hello = 1,
    server_hello = 2,
    new_session_ticket = 4,
    end_of_early_data = 5,
    encrypted_extensions = 8,
    certificate = 11,
    server_key_exchange = 12, // TLS 1.2
    certificate_request = 13,
    server_hello_done = 14, // TLS 1.2
    certificate_verify = 15,
    client_key_exchange = 16, // TLS 1.2
    finished = 20,
    key_update = 24,
    message_hash = 254,
    _,
};

/// Whether the TLS 1.2 client is built in: the `tls12` build option,
/// true unless `-Dtls12=false`. Without it the code is left out.
pub const tls12_enabled = @import("build_options").tls12;

pub const CipherSuite = enum(u16) {
    aes_128_gcm_sha256 = 0x1301,
    aes_256_gcm_sha384 = 0x1302,
    chacha20_poly1305_sha256 = 0x1303,
    // TLS 1.2: ECDHE with an AEAD (RFC 5289, RFC 7905).
    ecdhe_ecdsa_with_aes_128_gcm_sha256 = 0xc02b,
    ecdhe_ecdsa_with_aes_256_gcm_sha384 = 0xc02c,
    ecdhe_rsa_with_aes_128_gcm_sha256 = 0xc02f,
    ecdhe_rsa_with_aes_256_gcm_sha384 = 0xc030,
    ecdhe_rsa_with_chacha20_poly1305_sha256 = 0xcca8,
    ecdhe_ecdsa_with_chacha20_poly1305_sha256 = 0xcca9,
    /// Not a suite: a client's signal of secure renegotiation (RFC 5746).
    empty_renegotiation_info_scsv = 0x00ff,
    _,

    /// The TLS 1.3 suites.
    pub const all = [_]CipherSuite{ .aes_128_gcm_sha256, .aes_256_gcm_sha384, .chacha20_poly1305_sha256 };
    /// The TLS 1.2 suites a client may offer, in preference order. Listing
    /// any of them in a client's `cipher_suites` offers TLS 1.2, in a
    /// build with `tls12_enabled`.
    pub const tls12 = [_]CipherSuite{
        .ecdhe_ecdsa_with_aes_128_gcm_sha256,
        .ecdhe_rsa_with_aes_128_gcm_sha256,
        .ecdhe_ecdsa_with_chacha20_poly1305_sha256,
        .ecdhe_rsa_with_chacha20_poly1305_sha256,
        .ecdhe_ecdsa_with_aes_256_gcm_sha384,
        .ecdhe_rsa_with_aes_256_gcm_sha384,
    };

    /// The protocol version a suite belongs to, null for one ztls does
    /// not implement.
    pub fn version(suite: CipherSuite) ?Version {
        return switch (suite) {
            .aes_128_gcm_sha256, .aes_256_gcm_sha384, .chacha20_poly1305_sha256 => .tls_1_3,
            .ecdhe_ecdsa_with_aes_128_gcm_sha256,
            .ecdhe_ecdsa_with_aes_256_gcm_sha384,
            .ecdhe_rsa_with_aes_128_gcm_sha256,
            .ecdhe_rsa_with_aes_256_gcm_sha384,
            .ecdhe_rsa_with_chacha20_poly1305_sha256,
            .ecdhe_ecdsa_with_chacha20_poly1305_sha256,
            => .tls_1_2,
            else => null,
        };
    }
};

pub const Extension = enum(u16) {
    server_name = 0,
    max_fragment_length = 1,
    status_request = 5,
    supported_groups = 10,
    ec_point_formats = 11, // TLS 1.2
    signature_algorithms = 13,
    application_layer_protocol_negotiation = 16,
    signed_certificate_timestamp = 18,
    padding = 21,
    extended_master_secret = 23, // TLS 1.2
    session_ticket = 35, // TLS 1.2
    pre_shared_key = 41,
    early_data = 42,
    supported_versions = 43,
    cookie = 44,
    psk_key_exchange_modes = 45,
    certificate_authorities = 47,
    oid_filters = 48,
    post_handshake_auth = 49,
    signature_algorithms_cert = 50,
    key_share = 51,
    renegotiation_info = 0xff01, // TLS 1.2
    _,
};

pub const SignatureScheme = enum(u16) {
    rsa_pkcs1_sha256 = 0x0401,
    rsa_pkcs1_sha384 = 0x0501,
    rsa_pkcs1_sha512 = 0x0601,
    ecdsa_secp256r1_sha256 = 0x0403,
    ecdsa_secp384r1_sha384 = 0x0503,
    ecdsa_secp521r1_sha512 = 0x0603,
    rsa_pss_rsae_sha256 = 0x0804,
    rsa_pss_rsae_sha384 = 0x0805,
    rsa_pss_rsae_sha512 = 0x0806,
    ed25519 = 0x0807,
    ed448 = 0x0808,
    rsa_pss_pss_sha256 = 0x0809,
    rsa_pss_pss_sha384 = 0x080a,
    rsa_pss_pss_sha512 = 0x080b,
    rsa_pkcs1_sha1 = 0x0201,
    ecdsa_sha1 = 0x0203,
    _,
};

pub const NamedGroup = enum(u16) {
    secp256r1 = 0x0017,
    secp384r1 = 0x0018,
    secp521r1 = 0x0019,
    x25519 = 0x001d,
    x448 = 0x001e,
    ffdhe2048 = 0x0100,
    ffdhe3072 = 0x0101,
    ffdhe4096 = 0x0102,
    ffdhe6144 = 0x0103,
    ffdhe8192 = 0x0104,
    x25519_ml_kem768 = 0x11ec,
    _,
};

pub const PskKeyExchangeMode = enum(u8) {
    psk_ke = 0,
    psk_dhe_ke = 1,
    _,
};

pub const KeyUpdateRequest = enum(u8) {
    update_not_requested = 0,
    update_requested = 1,
    _,
};

pub const Side = enum { client, server };

pub const Alert = enum(u8) {
    close_notify = 0,
    unexpected_message = 10,
    bad_record_mac = 20,
    record_overflow = 22,
    handshake_failure = 40,
    bad_certificate = 42,
    unsupported_certificate = 43,
    certificate_revoked = 44,
    certificate_expired = 45,
    certificate_unknown = 46,
    illegal_parameter = 47,
    unknown_ca = 48,
    access_denied = 49,
    decode_error = 50,
    decrypt_error = 51,
    protocol_version = 70,
    insufficient_security = 71,
    internal_error = 80,
    inappropriate_fallback = 86,
    user_canceled = 90,
    no_renegotiation = 100, // TLS 1.2
    missing_extension = 109,
    unsupported_extension = 110,
    unrecognized_name = 112,
    bad_certificate_status_response = 113,
    unknown_psk_identity = 115,
    certificate_required = 116,
    general_error = 117,
    no_application_protocol = 120,
    _,

    pub const Level = enum(u8) {
        warning = 1,
        fatal = 2,
        _,
    };

    /// An alert the peer sent, as an error. `close_notify` and
    /// `user_canceled` are not failures and are not here.
    pub const Error = error{
        TlsAlertUnexpectedMessage,
        TlsAlertBadRecordMac,
        TlsAlertRecordOverflow,
        TlsAlertHandshakeFailure,
        TlsAlertBadCertificate,
        TlsAlertUnsupportedCertificate,
        TlsAlertCertificateRevoked,
        TlsAlertCertificateExpired,
        TlsAlertCertificateUnknown,
        TlsAlertIllegalParameter,
        TlsAlertUnknownCa,
        TlsAlertAccessDenied,
        TlsAlertDecodeError,
        TlsAlertDecryptError,
        TlsAlertProtocolVersion,
        TlsAlertInsufficientSecurity,
        TlsAlertInternalError,
        TlsAlertInappropriateFallback,
        TlsAlertNoRenegotiation,
        TlsAlertMissingExtension,
        TlsAlertUnsupportedExtension,
        TlsAlertUnrecognizedName,
        TlsAlertBadCertificateStatusResponse,
        TlsAlertUnknownPskIdentity,
        TlsAlertCertificateRequired,
        TlsAlertGeneralError,
        TlsAlertNoApplicationProtocol,
        TlsAlertUnknown,
    };

    /// Null for the two alerts that are not failures.
    pub fn toError(alert: Alert) ?Error {
        return switch (alert) {
            .close_notify, .user_canceled => null,
            .unexpected_message => error.TlsAlertUnexpectedMessage,
            .bad_record_mac => error.TlsAlertBadRecordMac,
            .record_overflow => error.TlsAlertRecordOverflow,
            .handshake_failure => error.TlsAlertHandshakeFailure,
            .bad_certificate => error.TlsAlertBadCertificate,
            .unsupported_certificate => error.TlsAlertUnsupportedCertificate,
            .certificate_revoked => error.TlsAlertCertificateRevoked,
            .certificate_expired => error.TlsAlertCertificateExpired,
            .certificate_unknown => error.TlsAlertCertificateUnknown,
            .illegal_parameter => error.TlsAlertIllegalParameter,
            .unknown_ca => error.TlsAlertUnknownCa,
            .access_denied => error.TlsAlertAccessDenied,
            .decode_error => error.TlsAlertDecodeError,
            .decrypt_error => error.TlsAlertDecryptError,
            .protocol_version => error.TlsAlertProtocolVersion,
            .insufficient_security => error.TlsAlertInsufficientSecurity,
            .internal_error => error.TlsAlertInternalError,
            .inappropriate_fallback => error.TlsAlertInappropriateFallback,
            .no_renegotiation => error.TlsAlertNoRenegotiation,
            .missing_extension => error.TlsAlertMissingExtension,
            .unsupported_extension => error.TlsAlertUnsupportedExtension,
            .unrecognized_name => error.TlsAlertUnrecognizedName,
            .bad_certificate_status_response => error.TlsAlertBadCertificateStatusResponse,
            .unknown_psk_identity => error.TlsAlertUnknownPskIdentity,
            .certificate_required => error.TlsAlertCertificateRequired,
            .general_error => error.TlsAlertGeneralError,
            .no_application_protocol => error.TlsAlertNoApplicationProtocol,
            _ => error.TlsAlertUnknown,
        };
    }

    /// True for the errors `toError` produces: the peer's failure, not ours.
    pub fn isFromPeer(err: anyerror) bool {
        inline for (comptime std.meta.fieldNames(Error)) |name| {
            if (err == @field(anyerror, name)) return true;
        }
        return false;
    }

    /// The alert to send for a failure we found, or null when the peer
    /// should not get one: it reported its own failure, or the transport
    /// is gone.
    pub fn forLocalError(err: anyerror) ?Alert {
        if (isFromPeer(err)) return null;
        return switch (err) {
            error.ReadFailed,
            error.WriteFailed,
            error.EndOfStream,
            error.TlsConnectionTruncated,
            error.TlsConnectionFailed,
            error.Canceled,
            => null,

            error.TlsUnexpectedMessage => .unexpected_message,
            error.TlsBadRecordMac => .bad_record_mac,
            error.TlsRecordOverflow => .record_overflow,
            error.TlsHandshakeFailure => .handshake_failure,
            error.TlsBadCertificate => .bad_certificate,
            error.TlsUnsupportedCertificate => .unsupported_certificate,
            error.TlsCertificateRevoked => .certificate_revoked,
            error.TlsCertificateUnknown => .certificate_unknown,
            error.TlsIllegalParameter => .illegal_parameter,
            error.TlsAccessDenied => .access_denied,
            error.TlsDecodeError => .decode_error,
            error.TlsDecryptError => .decrypt_error,
            error.TlsProtocolVersion => .protocol_version,
            error.TlsInsufficientSecurity => .insufficient_security,
            error.TlsInternalError => .internal_error,
            error.TlsInappropriateFallback => .inappropriate_fallback,
            error.TlsNoRenegotiation => .no_renegotiation,
            error.TlsMissingExtension => .missing_extension,
            error.TlsUnsupportedExtension => .unsupported_extension,
            error.TlsUnrecognizedName => .unrecognized_name,
            error.TlsBadCertificateStatusResponse => .bad_certificate_status_response,
            error.TlsUnknownPskIdentity => .unknown_psk_identity,
            error.TlsCertificateRequired => .certificate_required,
            error.TlsNoApplicationProtocol => .no_application_protocol,
            error.CertificateIssuerNotFound => .unknown_ca,
            error.CertificateExpired, error.CertificateNotYetValid => .certificate_expired,
            error.CertificateHostMismatch => .bad_certificate,
            else => .internal_error,
        };
    }

    /// The two-byte alert body. TLS 1.3 peers ignore the level (RFC 9846
    /// §6), but the closure alerts are sent as warnings for older ones.
    pub fn encode(alert: Alert) [2]u8 {
        const level: Level = switch (alert) {
            .close_notify, .user_canceled => .warning,
            else => .fatal,
        };
        return .{ @intFromEnum(level), @intFromEnum(alert) };
    }

    /// The description byte of an alert body. The level is ignored, as
    /// RFC 9846 §6 says it may be: every alert but two is fatal regardless.
    pub fn decode(body: *const [2]u8) Alert {
        return @enumFromInt(body[1]);
    }
};

/// Everything the record layer and handshake can fail with on their own,
/// before the transport's `ReadFailed`/`WriteFailed` and the peer's alerts
/// (`Alert.Error`).
pub const LocalError = error{
    /// The peer closed the transport inside a record, or without
    /// close_notify in strict mode.
    TlsConnectionTruncated,
    /// An earlier failure already ended the connection.
    TlsConnectionFailed,
    TlsUnexpectedMessage,
    TlsBadRecordMac,
    TlsRecordOverflow,
    TlsHandshakeFailure,
    TlsBadCertificate,
    TlsUnsupportedCertificate,
    TlsCertificateRevoked,
    TlsCertificateUnknown,
    TlsIllegalParameter,
    TlsAccessDenied,
    TlsDecodeError,
    TlsDecryptError,
    TlsProtocolVersion,
    TlsInsufficientSecurity,
    TlsInternalError,
    TlsInappropriateFallback,
    /// A TLS 1.2 server asked to renegotiate, which we never do.
    TlsNoRenegotiation,
    TlsMissingExtension,
    TlsUnsupportedExtension,
    TlsUnrecognizedName,
    TlsBadCertificateStatusResponse,
    TlsUnknownPskIdentity,
    TlsCertificateRequired,
    TlsNoApplicationProtocol,
    // What our own check of the peer's certificate can find, named as
    // std.crypto and tls.zig name them.
    CertificateIssuerNotFound,
    CertificateExpired,
    CertificateNotYetValid,
    CertificateHostMismatch,
};

const testing = std.testing;

test "every local error has an alert and every alert error is the peer's" {
    inline for (comptime std.meta.fieldNames(LocalError)) |name| {
        const err = @field(anyerror, name);
        try testing.expect(!Alert.isFromPeer(err));
        // The two connection-state errors are the only ones with no alert.
        const has_alert = err != error.TlsConnectionTruncated and err != error.TlsConnectionFailed;
        try testing.expectEqual(has_alert, Alert.forLocalError(err) != null);
    }
    inline for (comptime std.meta.fieldNames(Alert.Error)) |name| {
        const err = @field(anyerror, name);
        try testing.expect(Alert.isFromPeer(err));
        try testing.expectEqual(null, Alert.forLocalError(err));
    }
}

test "alerts round-trip through errors" {
    const alerts = [_]Alert{ .unexpected_message, .bad_record_mac, .decode_error, .no_application_protocol, .certificate_required, .general_error };
    for (alerts) |alert| {
        const err = alert.toError().?;
        try testing.expect(Alert.isFromPeer(err));
        try testing.expectEqual(alert, Alert.decode(&alert.encode()));
    }
    try testing.expectEqual(null, Alert.close_notify.toError());
    try testing.expectEqual(null, Alert.user_canceled.toError());
    try testing.expectEqual(error.TlsAlertUnknown, @as(Alert, @enumFromInt(200)).toError().?);
    try testing.expectEqualSlices(u8, &.{ 1, 0 }, &Alert.close_notify.encode());
    try testing.expectEqualSlices(u8, &.{ 2, 40 }, &Alert.handshake_failure.encode());
}

test "transport failures send no alert, unknown failures send internal_error" {
    try testing.expectEqual(null, Alert.forLocalError(error.ReadFailed));
    try testing.expectEqual(null, Alert.forLocalError(error.Canceled));
    try testing.expectEqual(Alert.internal_error, Alert.forLocalError(error.Unexpected).?);
    try testing.expectEqual(Alert.internal_error, Alert.forLocalError(error.OutOfMemory).?);
    try testing.expectEqual(Alert.protocol_version, Alert.forLocalError(error.TlsProtocolVersion).?);
}
