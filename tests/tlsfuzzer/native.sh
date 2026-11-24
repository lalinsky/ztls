# Sourced by run.sh with IMPL=native: what the native server does that
# tlsfuzzer does not expect. In `engine_args`, by script name, are
# arguments added to the script's entry in `tests`. -e leaves a probe
# out, and each one says why:
#   lenient  ztls takes what the script wants refused, as RFC 9846
#            allows

# The native server has no secp521r1 key exchange.
engine_args[test-tls13-ecdhe-curves.py]=$(excluding <<'PROBES'
sanity - secp521r1
secp521r1 - key share from other curve
secp521r1 - point at infinity
secp521r1 - point outside curve
secp521r1 - right 0-padded key_share
secp521r1 - right-truncated key_share
secp521r1 - x=0, y=0
PROBES
)
engine_args[test-tls13-dhe-shared-secret-padding.py]=$(excluding <<< 'TLS 1.3 with secp521r1')
engine_args[test-tls13-serverhello-random.py]=$(excluding <<< 'TLS 1.3 with secp521r1')
engine_args[test-tls13-obsolete-curves.py]=$(excluding <<< 'secp521r1 in supported_groups and key_share')

# Only these probes: the rest expect a fall back to TLS 1.2, which the
# server does not speak.
engine_args[test-tls13-version-negotiation.py]=" sanity 'tls 1.8 only' 'SSL 3.0 in supported version'
    'tls 1.3 negotiation with SSL 3.0 in record layer'
    'tls 1.3 negotiation with SSL 3.1 in record layer'
    'tls 1.3 negotiation with SSL 3.2 in record layer'
    'tls 1.3 negotiation with SSL 3.3 in record layer'
    'SSL 2.0 ClientHello with TLS 1.3 version and TLS 1.3 only ciphersuites'"

# lenient: more than one change_cipher_spec is dropped like the first, as
# RFC 9846 §5 has it ("at any time ... before the peer's Finished").
engine_args[test-tls13-multiple-ccs-messages.py]=$(excluding <<'PROBES'
second CCS before client finished
multiple CCS Messages in one TCP packet
CH and multiple CCS Messages in one TCP packet
PROBES
)
