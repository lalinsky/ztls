# Sourced by run.sh with IMPL=libssl: what AWS-LC's libssl does that
# tlsfuzzer does not expect. In `engine_args`, by script name, are
# arguments added to the script's entry in `tests`. -e leaves a probe
# out, and each one says why:
#   alert    AWS-LC refuses as it should, with a different alert
#   lenient  AWS-LC takes what the script wants refused, as RFC 8446
#            allows
#   strict   AWS-LC refuses what the script wants taken

# libssl's default takes TLS 1.2's SHA-1 schemes too.
sigalgs+=' ecdsa_sha1 rsa_pkcs1_sha1'

# alert: bad_record_mac, not unexpected_message, for a change_cipher_spec
# after Finished or a plaintext Finished: AWS-LC expects a record under
# the handshake keys.
engine_args[test-tls13-ccs.py]=$(excluding <<< 'CCS message after Finished message')
engine_args[test-tls13-finished-plaintext.py]=$(excluding <<< 'Unencrypted Finished message')

# alert: decode_error, not illegal_parameter, for an empty key share.
engine_args[test-tls13-crfg-curves.py]=$(excluding <<< 'empty x25519 key share')

# lenient: a legacy_version below TLS 1.2 next to supported_versions with
# TLS 1.3 is ignored (RFC 8446 §4.2.1), not refused with protocol_version.
engine_args[test-tls13-legacy-version.py]=$(excluding <<'PROBES'
version (0, 0)
version (0, 1)
version (0, 2)
version (1, 0)
version (1, 2)
version (1, 3)
version (2, 0)
version (3, 0)
PROBES
)

# alert: internal_error, not illegal_parameter, for an ML-KEM share
# whose coefficients are out of range, and decode_error for a padded one.
# --no-fuzz leaves out the 384 like it that vary every coefficient.
engine_args[test-tls13-mlkem.py]=" --no-fuzz$(excluding <<'PROBES'
x25519mlkem768: malformed pqc part, variable 0
x25519mlkem768: malformed pqc part, variable 1
x25519mlkem768: malformed pqc part, variable 2
x25519mlkem768: malformed pqc part, variable 3
x25519mlkem768: padded key share
PROBES
)"

# alert: decrypt_error, not unexpected_message, for a record of content
# type zero.
engine_args[test-tls13-zero-content-type.py]=$(excluding <<'PROBES'
zero content type after handshake
zero content type and padding during application data
zero content type during application data
zero content type during handshake
zero content type with padding after handshake
zero content type with padding during handshake
PROBES
)

# strict: tlsfuzzer sends the change_cipher_spec that follows a ClientHello
# with the ClientHello's record version, 0x0300, which AWS-LC refuses with
# protocol_version once it has picked TLS 1.3; RFC 8446 §5.1 says to
# ignore it. This one is refused, then, as are those with more than one.
# alert: protocol_version, not unexpected_message, for two in one record.
engine_args[test-tls13-multiple-ccs-messages.py]=$(excluding <<'PROBES'
sanity with one CCS message
second CCS before client finished
multiple CCS Messages in one TCP packet
CH and multiple CCS Messages in one TCP packet
multiple CCS Messages in one TLS record
PROBES
)

# alert: decrypt_error, not decode_error, for a Finished of the wrong
# length: AWS-LC compares it with what it expects before its length.
engine_args[test-tls13-finished.py]=$(excluding <<'PROBES'
empty - cipher TLS_AES_128_GCM_SHA256
empty - cipher TLS_AES_256_GCM_SHA384
padding - cipher TLS_AES_128_GCM_SHA256, pad_byte 0, pad_left 0, pad_right 1
padding - cipher TLS_AES_128_GCM_SHA256, pad_byte 0, pad_left 0, pad_right 2
padding - cipher TLS_AES_128_GCM_SHA256, pad_byte 0, pad_left 0, pad_right 4
padding - cipher TLS_AES_128_GCM_SHA256, pad_byte 0, pad_left 0, pad_right 8
padding - cipher TLS_AES_128_GCM_SHA256, pad_byte 0, pad_left 0, pad_right 16
padding - cipher TLS_AES_128_GCM_SHA256, pad_byte 0, pad_left 0, pad_right 32
padding - cipher TLS_AES_128_GCM_SHA256, pad_byte 0, pad_left 0, pad_right 48
padding - cipher TLS_AES_128_GCM_SHA256, pad_byte 0, pad_left 0, pad_right 16348
padding - cipher TLS_AES_128_GCM_SHA256, pad_byte 0, pad_left 1, pad_right 0
padding - cipher TLS_AES_128_GCM_SHA256, pad_byte 0, pad_left 1, pad_right 1
padding - cipher TLS_AES_128_GCM_SHA256, pad_byte 0, pad_left 2, pad_right 0
padding - cipher TLS_AES_128_GCM_SHA256, pad_byte 0, pad_left 4, pad_right 0
padding - cipher TLS_AES_128_GCM_SHA256, pad_byte 0, pad_left 8, pad_right 0
padding - cipher TLS_AES_128_GCM_SHA256, pad_byte 0, pad_left 8, pad_right 8
padding - cipher TLS_AES_128_GCM_SHA256, pad_byte 0, pad_left 12, pad_right 0
padding - cipher TLS_AES_128_GCM_SHA256, pad_byte 0, pad_left 16, pad_right 0
padding - cipher TLS_AES_128_GCM_SHA256, pad_byte 0, pad_left 32, pad_right 0
padding - cipher TLS_AES_128_GCM_SHA256, pad_byte 0, pad_left 48, pad_right 0
padding - cipher TLS_AES_128_GCM_SHA256, pad_byte 0, pad_left 16348, pad_right 0
padding - cipher TLS_AES_256_GCM_SHA384, pad_byte 0, pad_left 0, pad_right 1
padding - cipher TLS_AES_256_GCM_SHA384, pad_byte 0, pad_left 0, pad_right 2
padding - cipher TLS_AES_256_GCM_SHA384, pad_byte 0, pad_left 0, pad_right 4
padding - cipher TLS_AES_256_GCM_SHA384, pad_byte 0, pad_left 0, pad_right 8
padding - cipher TLS_AES_256_GCM_SHA384, pad_byte 0, pad_left 0, pad_right 12
padding - cipher TLS_AES_256_GCM_SHA384, pad_byte 0, pad_left 0, pad_right 16
padding - cipher TLS_AES_256_GCM_SHA384, pad_byte 0, pad_left 0, pad_right 32
padding - cipher TLS_AES_256_GCM_SHA384, pad_byte 0, pad_left 0, pad_right 48
padding - cipher TLS_AES_256_GCM_SHA384, pad_byte 0, pad_left 0, pad_right 16332
padding - cipher TLS_AES_256_GCM_SHA384, pad_byte 0, pad_left 1, pad_right 0
padding - cipher TLS_AES_256_GCM_SHA384, pad_byte 0, pad_left 1, pad_right 1
padding - cipher TLS_AES_256_GCM_SHA384, pad_byte 0, pad_left 2, pad_right 0
padding - cipher TLS_AES_256_GCM_SHA384, pad_byte 0, pad_left 4, pad_right 0
padding - cipher TLS_AES_256_GCM_SHA384, pad_byte 0, pad_left 8, pad_right 0
padding - cipher TLS_AES_256_GCM_SHA384, pad_byte 0, pad_left 8, pad_right 8
padding - cipher TLS_AES_256_GCM_SHA384, pad_byte 0, pad_left 16, pad_right 0
padding - cipher TLS_AES_256_GCM_SHA384, pad_byte 0, pad_left 32, pad_right 0
padding - cipher TLS_AES_256_GCM_SHA384, pad_byte 0, pad_left 48, pad_right 0
padding - cipher TLS_AES_256_GCM_SHA384, pad_byte 0, pad_left 16332, pad_right 0
truncation - cipher TLS_AES_128_GCM_SHA256, start 0, end 12
truncation - cipher TLS_AES_128_GCM_SHA256, start 0, end -1
truncation - cipher TLS_AES_128_GCM_SHA256, start 0, end -2
truncation - cipher TLS_AES_128_GCM_SHA256, start 0, end -4
truncation - cipher TLS_AES_128_GCM_SHA256, start 0, end -8
truncation - cipher TLS_AES_128_GCM_SHA256, start 0, end -16
truncation - cipher TLS_AES_128_GCM_SHA256, start 0, end -32
truncation - cipher TLS_AES_128_GCM_SHA256, start 1, end None
truncation - cipher TLS_AES_128_GCM_SHA256, start 2, end None
truncation - cipher TLS_AES_128_GCM_SHA256, start 4, end None
truncation - cipher TLS_AES_128_GCM_SHA256, start 8, end None
truncation - cipher TLS_AES_128_GCM_SHA256, start 16, end None
truncation - cipher TLS_AES_128_GCM_SHA256, start 32, end None
truncation - cipher TLS_AES_256_GCM_SHA384, start 0, end 12
truncation - cipher TLS_AES_256_GCM_SHA384, start 0, end -1
truncation - cipher TLS_AES_256_GCM_SHA384, start 0, end -2
truncation - cipher TLS_AES_256_GCM_SHA384, start 0, end -4
truncation - cipher TLS_AES_256_GCM_SHA384, start 0, end -8
truncation - cipher TLS_AES_256_GCM_SHA384, start 0, end -16
truncation - cipher TLS_AES_256_GCM_SHA384, start 0, end -32
truncation - cipher TLS_AES_256_GCM_SHA384, start 1, end None
truncation - cipher TLS_AES_256_GCM_SHA384, start 2, end None
truncation - cipher TLS_AES_256_GCM_SHA384, start 4, end None
truncation - cipher TLS_AES_256_GCM_SHA384, start 8, end None
truncation - cipher TLS_AES_256_GCM_SHA384, start 16, end None
truncation - cipher TLS_AES_256_GCM_SHA384, start 32, end None
PROBES
)

# alert: decode_error, not illegal_parameter, for a KeyUpdate whose
# request_update is not 0 or 1.
engine_args[test-tls13-keyupdate.py]=$(for type in $(seq 2 255); do echo "invalid message_type - $type, in KeyUpdate msg"; done | excluding)

# alert: bad_record_mac, not record_overflow, for a ciphertext over the
# limit with a bad tag: AWS-LC checks the tag first. decrypt_error, not
# decode_error, for a Finished padded to the record limit.
engine_args[test-tls13-record-layer-limits.py]=$(
    for val in 1 2 4 8 16 32 64 128; do
        for pos in $(seq -1 -1 -16); do
            echo "too big ciphertext with size 2**14 + 256 andfuzzed tag with $val on pos $pos"
        done
    done | excluding
    excluding <<'PROBES'
max size payload (2**14) of Finished msg, with 16348 bytes of left padding, cipher TLS_AES_128_GCM_SHA256
max size payload (2**14) of Finished msg, with 16348 bytes of left padding, cipher TLS_CHACHA20_POLY1305_SHA256
PROBES
)

# alert: decrypt_error, not illegal_parameter, for a CertificateVerify
# under a scheme the client's key or TLS 1.3 does not allow.
engine_args[test-tls13-certificate-verify.py]=$(excluding <<'PROBES'
check rsa_pkcs1_sha1 signature is refused
check rsa_pkcs1_sha256 signature is refused
check rsa_pkcs1_sha384 signature is refused
check rsa_pkcs1_sha512 signature is refused
PROBES
)
engine_args[test-tls13-ecdsa-in-certificate-verify.py]=$(excluding <<'PROBES'
check ecdsa_secp384r1_sha384 signature is refused
check ecdsa_secp521r1_sha512 signature is refused
check ecdsa_sha1 signature is refused
PROBES
)
engine_args[test-tls13-eddsa-in-certificate-verify.py]=$(excluding <<'PROBES'
check ecdsa_secp256r1_sha256 signature is refused
check ecdsa_secp384r1_sha384 signature is refused
check ecdsa_secp521r1_sha512 signature is refused
check ecdsa_sha1 signature is refused
PROBES
)
