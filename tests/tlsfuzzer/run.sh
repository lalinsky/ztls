#!/usr/bin/env bash
# Runs tlsfuzzer's TLS 1.3 scripts against ztls's server (server.zig),
# built with the engine IMPL names: native (the default) or libssl.
#
# Needs Python 3 with venv. tlsfuzzer and its Python packages go under
# .tlsfuzzer/ in the repository, made on the first run and reused.
# Arguments pick scripts by name, e.g. test-tls13-hrr.py; without any, all
# of them run, PARALLEL (default 4) at a time. Each script's output is
# kept in .tlsfuzzer/out/, the server's in .tlsfuzzer/server.log.
set -euo pipefail
cd "$(dirname "$0")/../.."

: "${ZIG:=zig}"
: "${PYTHON:=python3}"
# The engine the server is built with: native or libssl.
: "${IMPL:=native}"
: "${PARALLEL:=4}"
: "${TLSFUZZER:=.tlsfuzzer/tlsfuzzer}"
# Pinned: the scripts and what they expect change.
: "${TLSFUZZER_REV:=5eebc4464e5197a7f7392fb9acda99cfc32441f7}"
# tlslite-ng as the pinned tlsfuzzer's requirements.txt has it, and
# kyber-py for its ML-KEM.
python_packages=(tlslite-ng==0.9.0b2 kyber-py==1.2.0)

if [ ! -d "$TLSFUZZER" ]; then
    git init -q "$TLSFUZZER"
    git -C "$TLSFUZZER" remote add origin https://github.com/tlsfuzzer/tlsfuzzer
fi
if [ "$(git -C "$TLSFUZZER" rev-parse --verify -q HEAD)" != "$TLSFUZZER_REV" ]; then
    git -C "$TLSFUZZER" fetch -q --depth 1 origin "$TLSFUZZER_REV"
    git -C "$TLSFUZZER" checkout -q "$TLSFUZZER_REV"
fi
venv=.tlsfuzzer/venv
if [ "$(cat "$venv/packages" 2>/dev/null)" != "${python_packages[*]}" ]; then
    rm -rf "$venv"
    "$PYTHON" -m venv "$venv"
    "$venv/bin/pip" install -q "${python_packages[@]}"
    echo "${python_packages[*]}" > "$venv/packages"
fi

"$ZIG" build tlsfuzzer-server -Dimpl="$IMPL"

root=$PWD
clients=$root/tests/tlsfuzzer
pki=$root/src/testdata/pki
# What the server takes in a client's CertificateVerify.
sigalgs='ecdsa_secp256r1_sha256 ecdsa_secp384r1_sha384 ecdsa_secp521r1_sha512 ed25519 rsa_pss_rsae_sha256 rsa_pss_rsae_sha384 rsa_pss_rsae_sha512 rsa_pkcs1_sha256 rsa_pkcs1_sha384 rsa_pkcs1_sha512'

# Prints an -e for each probe named on stdin, one per line.
excluding() {
    local probe
    while IFS= read -r probe; do
        [ -n "$probe" ] && printf " -e '%s'" "$probe"
    done
}

# Every probe of test-tls13-symetric-ciphers.py for a CCM suite.
ccm_probes() {
    local suite n val pos what
    for suite in TLS_AES_128_CCM_SHA256:17 TLS_AES_128_CCM_8_SHA256:9; do
        n=${suite#*:}
        suite=${suite%:*}
        echo "check connection with $suite"
        for val in 1 2 4 8 16 32 64 128; do
            for ((pos = -1; pos > -n; pos--)); do
                for what in 'application data' 'finished message'; do
                    echo "check connection with $suite - fuzz tag on $what with $val on pos $pos"
                done
            done
        done
    done
}

# Every probe of test-tls13-obsolete-curves.py with a key share for an
# obsolete group that supported_groups does not list.
inconsistent_share_probes() {
    local group
    for group in brainpoolP256r1 brainpoolP384r1 brainpoolP512r1 \
        secp160k1 secp160r1 secp160r2 secp192k1 secp192r1 secp224k1 secp224r1 secp256k1 \
        sect163k1 sect163r1 sect163r2 sect193r1 sect193r2 sect233k1 sect233r1 sect239k1 \
        sect283k1 sect283r1 sect409k1 sect409r1 sect571k1 sect571r1 \
        'unknown (65281)' 'unknown (65282)'; do
        echo "$group in key_share and secp256r1 in supported_groups (inconsistent extensions)"
    done
}

# What each engine does differently, in native.sh and libssl.sh: by
# script name, arguments added to the script's entry below.
declare -A engine_args
source "$clients/$IMPL.sh"

# One script per entry: its name and arguments, split as the shell would.
# These hold for both engines. -e leaves a probe out, and each one says
# why:
#   unsupported  a feature neither engine has
#   alert        both refuse as they should, with a different alert
#   limit        both refuse a handshake message over 16 KiB, with
#                illegal_parameter
#
# Scripts left out altogether:
#   test-tls13-0rtt-garbage.py, -psk_dhe_ke.py, -psk_ke.py,
#   -session-resumption.py, -count-tickets.py beyond -t 0: no PSK,
#     tickets or 0-RTT; a ClientHello with early_data is refused.
#   test-tls13-ffdhe-groups.py, -ffdhe-sanity.py, -ecdhe-brainpool-curves.py,
#   -ecdsa-brainpool-in-certificate-verify.py,
#   -mldsa-in-certificate-verify.py: unsupported groups and signatures.
#   test-tls13-rsapss-signatures.py: needs an RSASSA-PSS (rsa_pss_pss_*)
#     server key, which ztls does not support.
#   test-tls13-certificate-compression.py,
#   -client-certificate-compression.py: no certificate compression; a
#     malformed compress_certificate extension is ignored like any other
#     unknown extension.
#   test-tls13-post-handshake-auth.py: no post-handshake authentication.
#   test-tls13-non-support.py: for servers without TLS 1.3.
#   test-tls13-minerva.py: a timing analysis that wants packet capture
#     and hours; the ECDSA signing is AWS-LC's.
#   test-tls13-large-number-of-extensions.py: every probe but sanity
#     sends 1024 to 4096 extensions, past 16 KiB or past the 64 extension
#     types a ClientHello may carry (refused with decode_error).
#   test-tls13-shuffled-extentions.py: every probe but sanity either sends
#     thousands of extensions (as above) or checks that a second
#     ClientHello repeats the first one's extension order, which ztls
#     does not compare (as BoringSSL does not).
tests=(
    "test-tls13-conversation.py"
    "test-tls13-ccs.py"
    "test-tls13-connection-abort.py $(excluding <<< 'After NewSessionTicket')"
        # unsupported: no tickets
    "test-tls13-count-tickets.py -t 0"
    "test-tls13-crfg-curves.py $(excluding <<'PROBES'
sanity x448 with compression ansiX962_compressed_char2
sanity x448 with compression ansiX962_compressed_prime
sanity x448 with compression uncompressed
all zero x448 key share
empty x448 key share
too big x448 key share
too small x448 key share
x448 key share of "1"
PROBES
)"
        # unsupported: x448
    "test-tls13-ecdhe-curves.py $(excluding <<'PROBES'
sanity - secp521r1
secp521r1 - key share from other curve
secp521r1 - point at infinity
secp521r1 - point outside curve
secp521r1 - right 0-padded key_share
secp521r1 - right-truncated key_share
secp521r1 - x=0, y=0
sanity - x448
x448 - key share from other curve
x448 - point at infinity
x448 - right 0-padded key_share
x448 - right-truncated key_share
PROBES
)"
        # unsupported: secp521r1, x448
    "test-tls13-dhe-shared-secret-padding.py $(excluding <<'PROBES'
TLS 1.3 with secp521r1
TLS 1.3 with x448
TLS 1.3 with ffdhe2048
TLS 1.3 with ffdhe3072
PROBES
)"
        # unsupported groups
    "test-tls13-serverhello-random.py $(excluding <<'PROBES'
TLS 1.3 with secp521r1
TLS 1.3 with x448
TLS 1.3 with ffdhe2048
TLS 1.3 with ffdhe3072
PROBES
)"
        # unsupported groups
    "test-tls13-obsolete-curves.py --relaxed -a handshake_failure $(excluding <<'PROBES'
secp521r1 in supported_groups and key_share
x448 in supported_groups and key_share
PROBES
)$(inconsistent_share_probes | excluding)"
        # --relaxed: obsolete groups next to a supported one are ignored,
        # not refused, which RFC 9846 does not ask for. -a: with nothing
        # else, no common group is handshake_failure. unsupported:
        # secp521r1, x448. A share for a group we do not support is
        # ignored, as Go does, even if supported_groups does not list it
        # (§4.2.8 allows it).
    "test-tls13-mlkem.py --kems x25519mlkem768"     # the hybrid both have
    "test-tls13-no-unknown-groups.py
        --groups x25519mlkem768,x25519,secp256r1,secp384r1"
        # --groups: ours, in our order, as the retry picks our favourite.
    "test-tls13-unrecognised-groups.py $(excluding <<'PROBES'
known group ffdhe2048 and unknown groups from EC range, key_share of size 64
known group ffdhe2048 and unknown groups from EC range, key_share of size 128
known group ffdhe2048 and unknown groups from EC range, key_share of size 256
known group ffdhe2048 and unknown groups from FFDHE range, key_share of size 64
known group ffdhe2048 and unknown groups from FFDHE range, key_share of size 128
known group ffdhe2048 and unknown groups from FFDHE range, key_share of size 256
only unknown key_share from EC range, key_share of size 64 + ffdhe2048 in supported_groups
only unknown key_share from EC range, key_share of size 128 + ffdhe2048 in supported_groups
only unknown key_share from EC range, key_share of size 256 + ffdhe2048 in supported_groups
only unknown key_share from FFDHE range, key_share of size 64 + ffdhe2048 in supported_groups
only unknown key_share from FFDHE range, key_share of size 128 + ffdhe2048 in supported_groups
only unknown key_share from FFDHE range, key_share of size 256 + ffdhe2048 in supported_groups
known group secp256r1 and unknown groups from EC range, key_share of size 128
known group secp256r1 and unknown groups from EC range, key_share of size 256
known group secp256r1 and unknown groups from FFDHE range, key_share of size 64
known group secp256r1 and unknown groups from FFDHE range, key_share of size 128
known group secp256r1 and unknown groups from FFDHE range, key_share of size 256
only unknown key_share from EC range, key_share of size 128 + secp256r1 in supported_groups
only unknown key_share from EC range, key_share of size 256 + secp256r1 in supported_groups
only unknown key_share from FFDHE range, key_share of size 64 + secp256r1 in supported_groups
only unknown key_share from FFDHE range, key_share of size 128 + secp256r1 in supported_groups
only unknown key_share from FFDHE range, key_share of size 256 + secp256r1 in supported_groups
only unknown supported_groups from EC range, key_share of size 128
only unknown supported_groups from EC range, key_share of size 256
only unknown supported_groups from FFDHE range, key_share of size 64
only unknown supported_groups from FFDHE range, key_share of size 128
only unknown supported_groups from FFDHE range, key_share of size 256
PROBES
)"
        # The ffdhe2048 ones are unsupported; the rest are limit.
    "test-tls13-signature-algorithms.py $(excluding <<'PROBES'
8130 invalid schemes
duplicated 8130 non-rsa schemes
tolerance 8130 methods
23752 invalid schemes
duplicated 23752 non-rsa schemes
tolerance 23752 methods
32715 invalid schemes
duplicated 32715 non-rsa schemes
tolerance 32715 methods
tolerance 32715 methods with sig_alg_cert
PROBES
)"
        # limit: the bigger lists make the ClientHello over 16 KiB.
    "test-tls13-legacy-version.py"
    "test-tls13-version-negotiation.py"
    "test-tls13-hrr.py"
    "test-tls13-finished.py $(excluding <<'PROBES'
padding - cipher TLS_AES_128_GCM_SHA256, pad_byte 0, pad_left 0, pad_right 131072
padding - cipher TLS_AES_128_GCM_SHA256, pad_byte 0, pad_left 0, pad_right 196608
padding - cipher TLS_AES_128_GCM_SHA256, pad_byte 0, pad_left 0, pad_right 16777183
padding - cipher TLS_AES_256_GCM_SHA384, pad_byte 0, pad_left 0, pad_right 131072
padding - cipher TLS_AES_256_GCM_SHA384, pad_byte 0, pad_left 0, pad_right 196608
padding - cipher TLS_AES_256_GCM_SHA384, pad_byte 0, pad_left 0, pad_right 16777167
PROBES
)"
        # limit: a Finished over 16 KiB, which the script wants refused
        # with decode_error
    "test-tls13-finished-plaintext.py"
    "test-tls13-invalid-ciphers.py"
    "test-tls13-nociphers.py"
    "test-tls13-keyshare-omitted.py"
    "test-tls13-record-layer-limits.py"
    "test-tls13-record-padding.py"
    "test-tls13-zero-content-type.py"
    "test-tls13-zero-length-data.py"
    "test-tls13-empty-alert.py $(
        for keys in handshake application; do
            for pad in 'no padding' '2 bytes of padding' '5 bytes of padding' '30 bytes of padding'; do
                echo "empty alert with $pad using $keys keys"
            done
        done | excluding
    )"
        # alert: decode_error for an empty alert record, not unexpected_message
    "test-tls13-unencrypted-alert.py $(excluding <<< 'unencrypted Alert')"
        # alert: a plaintext alert after the server's flight is answered
        # with unexpected_message (native) or bad_record_mac (libssl)
        # before closing, not just closed
    "test-tls13-multiple-ccs-messages.py"
    "test-tls13-keyupdate.py --coalescing
        $(excluding <<< 'app data split, conversation with KeyUpdate msg')"
        # --coalescing: all the requests read before a write are answered
        # by one KeyUpdate, as RFC 9846 §4.6.3 says of a peer that receives
        # several while it is silent. The split one expects that KeyUpdate
        # before the server has anything to write; RFC 9846 asks for it
        # before the next application data, which is when both send it.
    "test-tls13-keyupdate-from-server.py"
    "test-tls13-pkcs-signature.py"
    "test-tls13-rsa-signatures.py"
    "test-tls13-symetric-ciphers.py $(ccm_probes | excluding)"   # unsupported: CCM suites
    "test-tls13-lengths.py -p 4435 -n 100"
    "test-tls13-ecdsa-support.py -p 4436 $(excluding <<'PROBES'
Test with ecdsa_secp384r1_sha384
Test with ecdsa_secp521r1_sha512
Test with ecdsa_brainpoolP256r1tls13_sha256
Test with ecdsa_brainpoolP384r1tls13_sha384
Test with ecdsa_brainpoolP512r1tls13_sha512
PROBES
)"
        # a P-256 key signs with ecdsa_secp256r1_sha256 only; brainpool unsupported
    "test-tls13-ecdsa-support.py -p 4438 $(excluding <<'PROBES'
Test with ecdsa_secp256r1_sha256
Test with ecdsa_secp521r1_sha512
Test with ecdsa_brainpoolP256r1tls13_sha256
Test with ecdsa_brainpoolP384r1tls13_sha384
Test with ecdsa_brainpoolP512r1tls13_sha512
PROBES
)"
        # the same for a P-384 key
    "test-tls13-eddsa.py -p 4437 $(excluding <<< 'ed448 only')"  # unsupported: Ed448
    "test-tls13-certificate-request.py -p 4434 -s '$sigalgs'
        -c '$clients/client-rsa.pem' -k '$clients/client-rsa.key'"
    "test-tls13-certificate-verify.py -p 4434 -s '$sigalgs'
        -c '$clients/client-rsa.pem' -k '$clients/client-rsa.key'"
    "test-tls13-ecdsa-in-certificate-verify.py -p 4434 -s '$sigalgs'
        -c '$pki/client.pem' -k '$pki/client.key'"
    "test-tls13-eddsa-in-certificate-verify.py -p 4434 -s '$sigalgs'
        -c '$clients/client-ed25519.pem' -k '$clients/client-ed25519.key'"
)
for i in "${!tests[@]}"; do
    name=${tests[$i]%%[[:space:]]*}
    tests[$i]+=${engine_args[$name]:-}
done

out=$root/.tlsfuzzer/out
rm -rf "$out"
mkdir -p "$out"

zig-out/bin/tlsfuzzer-server > .tlsfuzzer/server.log 2>&1 &
server=$!
trap 'kill $server 2>/dev/null || true' EXIT
for _ in $(seq 100); do
    grep -q listening .tlsfuzzer/server.log && break
    kill -0 $server
    sleep 0.1
done

# Runs one entry of `tests`, from the tlsfuzzer checkout.
run() {
    local entry=${1//$'\n'/ }
    local name=${entry%% *}
    local port
    port=$(grep -oE -- '-p [0-9]+' <<< "$entry" | tr -d ' -' || true)
    local log=$out/${name%.py}${port:+-$port}.log
    if (cd "$TLSFUZZER" && eval "PYTHONPATH=. timeout 1800 '$python' scripts/$entry") > "$log" 2>&1; then
        echo "pass  $name $port"
    else
        echo "FAIL  $name $port (${log#"$root"/})"
        return 1
    fi
}
export -f run
export TLSFUZZER root out
export python=$root/$venv/bin/python

selected=()
for t in "${tests[@]}"; do
    name=${t%%[[:space:]]*}
    if [ $# -eq 0 ]; then
        selected+=("$t")
    else
        for arg in "$@"; do
            if [ "$arg" = "$name" ]; then selected+=("$t"); fi
        done
    fi
done

status=0
printf '%s\0' "${selected[@]}" | xargs -0 -n 1 -P "$PARALLEL" bash -c 'run "$1"' _ || status=1
kill -0 $server || { echo "the server died; see .tlsfuzzer/server.log" >&2; status=1; }
exit $status
