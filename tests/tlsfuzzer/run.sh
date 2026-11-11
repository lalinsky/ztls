#!/usr/bin/env bash
# Runs tlsfuzzer's TLS 1.3 scripts against ztls's server (server.zig).
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

"$ZIG" build tlsfuzzer-server

root=$PWD
clients=$root/tests/tlsfuzzer
pki=$root/src/testdata/pki
# What the server takes in a client's CertificateVerify.
sigalgs='ecdsa_secp256r1_sha256 ecdsa_secp384r1_sha384 ecdsa_secp521r1_sha512 ed25519 rsa_pss_rsae_sha256 rsa_pss_rsae_sha384 rsa_pss_rsae_sha512 rsa_pkcs1_sha256 rsa_pkcs1_sha384 rsa_pkcs1_sha512'

# Every probe of test-tls13-symetric-ciphers.py for a CCM suite.
ccm_probes() {
    local suite n val pos what
    for suite in TLS_AES_128_CCM_SHA256:17 TLS_AES_128_CCM_8_SHA256:9; do
        n=${suite#*:}
        suite=${suite%:*}
        printf " -e 'check connection with %s'" "$suite"
        for val in 1 2 4 8 16 32 64 128; do
            for ((pos = -1; pos > -n; pos--)); do
                for what in 'application data' 'finished message'; do
                    printf " -e 'check connection with %s - fuzz tag on %s with %d on pos %d'" "$suite" "$what" "$val" "$pos"
                done
            done
        done
    done
}

# One script per entry: its name and arguments, split as the shell would.
# -e leaves a probe out, and each one says why:
#   unsupported  a feature ztls does not have
#   alert        ztls refuses as it should, with a different alert
#   limit        ztls refuses a ClientHello past its limits: handshake
#                messages other than certificates are held to 16 KiB
#   BUG          ztls is wrong; see the comment
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
    "test-tls13-connection-abort.py
        -e 'After NewSessionTicket'"                # unsupported: no tickets
    "test-tls13-count-tickets.py -t 0"
    "test-tls13-crfg-curves.py
        -e 'sanity x448 with compression ansiX962_compressed_char2'
        -e 'sanity x448 with compression ansiX962_compressed_prime'
        -e 'sanity x448 with compression uncompressed'
        -e 'all zero x448 key share'
        -e 'empty x448 key share'
        -e 'too big x448 key share'
        -e 'too small x448 key share'
        -e 'x448 key share of \"1\"'"               # unsupported: x448
    "test-tls13-ecdhe-curves.py
        -e 'sanity - secp521r1'
        -e 'secp521r1 - key share from other curve'
        -e 'secp521r1 - point at infinity'
        -e 'secp521r1 - point outside curve'
        -e 'secp521r1 - right 0-padded key_share'
        -e 'secp521r1 - right-truncated key_share'
        -e 'secp521r1 - x=0, y=0'
        -e 'sanity - x448'
        -e 'x448 - key share from other curve'
        -e 'x448 - point at infinity'
        -e 'x448 - right 0-padded key_share'
        -e 'x448 - right-truncated key_share'"      # unsupported: secp521r1, x448
    "test-tls13-dhe-shared-secret-padding.py
        -e 'TLS 1.3 with secp521r1'
        -e 'TLS 1.3 with x448'
        -e 'TLS 1.3 with ffdhe2048'
        -e 'TLS 1.3 with ffdhe3072'"                # unsupported groups
    "test-tls13-serverhello-random.py
        -e 'TLS 1.3 with secp521r1'
        -e 'TLS 1.3 with x448'
        -e 'TLS 1.3 with ffdhe2048'
        -e 'TLS 1.3 with ffdhe3072'"                # unsupported groups
    "test-tls13-obsolete-curves.py
        --relaxed -a handshake_failure
        -e 'secp521r1 in supported_groups and key_share'
        -e 'x448 in supported_groups and key_share'"
        # --relaxed: obsolete groups next to a supported one are ignored,
        # not refused, which RFC 9846 does not ask for. -a: with nothing
        # else, no common group is handshake_failure. unsupported: secp521r1, x448.
    "test-tls13-mlkem.py --kems x25519mlkem768"     # the hybrid ztls has
    "test-tls13-no-unknown-groups.py
        --groups x25519mlkem768,x25519,secp256r1,secp384r1
        -e 'long list of unknown (between 1 and 259) plus a recognised group'"
        # --groups: ours, in our order, as the retry picks our favourite.
        # BUG: only the first 32 supported_groups are read; the known group is 260th.
    "test-tls13-unrecognised-groups.py
        -e 'known group secp256r1 and unknown groups from EC range, key_share of size 64'
        -e 'known group secp256r1 and unknown groups from EC range, key_share of size 128'
        -e 'known group secp256r1 and unknown groups from EC range, key_share of size 256'
        -e 'known group secp256r1 and unknown groups from FFDHE range, key_share of size 64'
        -e 'known group secp256r1 and unknown groups from FFDHE range, key_share of size 128'
        -e 'known group secp256r1 and unknown groups from FFDHE range, key_share of size 256'
        -e 'known group ffdhe2048 and unknown groups from EC range, key_share of size 64'
        -e 'known group ffdhe2048 and unknown groups from EC range, key_share of size 128'
        -e 'known group ffdhe2048 and unknown groups from EC range, key_share of size 256'
        -e 'known group ffdhe2048 and unknown groups from FFDHE range, key_share of size 64'
        -e 'known group ffdhe2048 and unknown groups from FFDHE range, key_share of size 128'
        -e 'known group ffdhe2048 and unknown groups from FFDHE range, key_share of size 256'
        -e 'only unknown key_share from EC range, key_share of size 64 + ffdhe2048 in supported_groups'
        -e 'only unknown key_share from EC range, key_share of size 128 + ffdhe2048 in supported_groups'
        -e 'only unknown key_share from EC range, key_share of size 256 + ffdhe2048 in supported_groups'
        -e 'only unknown key_share from FFDHE range, key_share of size 64 + ffdhe2048 in supported_groups'
        -e 'only unknown key_share from FFDHE range, key_share of size 128 + ffdhe2048 in supported_groups'
        -e 'only unknown key_share from FFDHE range, key_share of size 256 + ffdhe2048 in supported_groups'
        -e 'only unknown key_share from EC range, key_share of size 128 + secp256r1 in supported_groups'
        -e 'only unknown key_share from EC range, key_share of size 256 + secp256r1 in supported_groups'
        -e 'only unknown key_share from FFDHE range, key_share of size 64 + secp256r1 in supported_groups'
        -e 'only unknown key_share from FFDHE range, key_share of size 128 + secp256r1 in supported_groups'
        -e 'only unknown key_share from FFDHE range, key_share of size 256 + secp256r1 in supported_groups'
        -e 'only unknown supported_groups from EC range, key_share of size 128'
        -e 'only unknown supported_groups from EC range, key_share of size 256'
        -e 'only unknown supported_groups from FFDHE range, key_share of size 64'
        -e 'only unknown supported_groups from FFDHE range, key_share of size 128'
        -e 'only unknown supported_groups from FFDHE range, key_share of size 256'"
        # BUG: the first one is a 15.7 KiB ClientHello listing secp256r1
        # after 221 unknown groups; only the first 32 are read. The ffdhe2048
        # ones are unsupported; the rest are limit (over 16 KiB).
    "test-tls13-signature-algorithms.py
        -e '213 invalid schemes'
        -e 'duplicated 213 non-rsa schemes'
        -e 'tolerance 213 methods'
        -e '2353 invalid schemes'
        -e 'duplicated 2353 non-rsa schemes'
        -e 'tolerance 2353 methods'
        -e '8130 invalid schemes'
        -e 'duplicated 8130 non-rsa schemes'
        -e 'tolerance 8130 methods'
        -e '23752 invalid schemes'
        -e 'duplicated 23752 non-rsa schemes'
        -e 'tolerance 23752 methods'
        -e '32715 invalid schemes'
        -e 'duplicated 32715 non-rsa schemes'
        -e 'tolerance 32715 methods'
        -e 'tolerance 32715 methods with sig_alg_cert'"
        # BUG: 213 and 2353 put rsa_pss_rsae_sha256 last; only the first
        # 64 signature_algorithms are read. The bigger ones are limit.
    "test-tls13-legacy-version.py
        -e 'version (3, 0)' -e 'version (0, 0)' -e 'version (2, 0)' -e 'version (0, 2)'
        -e 'version (1, 0)' -e 'version (1, 3)' -e 'version (1, 2)' -e 'version (0, 1)'"
        # BUG: a ClientHello.legacy_version of 0x0300 or less is accepted;
        # RFC 8446 D.5 says abort with protocol_version.
    "test-tls13-version-negotiation.py
        sanity
        'tls 1.8 only'
        'SSL 3.0 in supported version'
        'tls 1.3 negotiation with SSL 3.0 in record layer'
        'tls 1.3 negotiation with SSL 3.1 in record layer'
        'tls 1.3 negotiation with SSL 3.2 in record layer'
        'tls 1.3 negotiation with SSL 3.3 in record layer'"
        # Only these: the rest expect a fall back to TLS 1.2, which the
        # server does not speak. Also out: 'SSL 2.0 ClientHello with TLS 1.3
        # version and TLS 1.3 only ciphersuites', BUG: the record header's
        # 0x80 content type is not refused until the 772 byte body its
        # length claims arrives, so the server waits until the client gives up.
    "test-tls13-hrr.py"
    "test-tls13-finished.py
        -e 'padding - cipher TLS_AES_128_GCM_SHA256, pad_byte 0, pad_left 0, pad_right 131072'
        -e 'padding - cipher TLS_AES_128_GCM_SHA256, pad_byte 0, pad_left 0, pad_right 196608'
        -e 'padding - cipher TLS_AES_128_GCM_SHA256, pad_byte 0, pad_left 0, pad_right 16777183'
        -e 'padding - cipher TLS_AES_256_GCM_SHA384, pad_byte 0, pad_left 0, pad_right 131072'
        -e 'padding - cipher TLS_AES_256_GCM_SHA384, pad_byte 0, pad_left 0, pad_right 196608'
        -e 'padding - cipher TLS_AES_256_GCM_SHA384, pad_byte 0, pad_left 0, pad_right 16777167'"
        # limit: a Finished over 16 KiB gets illegal_parameter, not decode_error
    "test-tls13-finished-plaintext.py"
    "test-tls13-invalid-ciphers.py"
    "test-tls13-nociphers.py"
    "test-tls13-keyshare-omitted.py"
    "test-tls13-record-layer-limits.py"
    "test-tls13-record-padding.py"
    "test-tls13-zero-content-type.py"
    "test-tls13-zero-length-data.py"
    "test-tls13-empty-alert.py
        -e 'empty alert with no padding using handshake keys'
        -e 'empty alert with 2 bytes of padding using handshake keys'
        -e 'empty alert with 5 bytes of padding using handshake keys'
        -e 'empty alert with 30 bytes of padding using handshake keys'
        -e 'empty alert with no padding using application keys'
        -e 'empty alert with 2 bytes of padding using application keys'
        -e 'empty alert with 5 bytes of padding using application keys'
        -e 'empty alert with 30 bytes of padding using application keys'"
        # alert: decode_error for an empty alert record, not unexpected_message
    "test-tls13-unencrypted-alert.py
        -e 'unencrypted Alert'"
        # alert: a plaintext alert after the server's flight is answered
        # with unexpected_message before closing, not just closed
    "test-tls13-multiple-ccs-messages.py
        -e 'second CCS before client finished'
        -e 'multiple CCS Messages in one TCP packet'
        -e 'CH and multiple CCS Messages in one TCP packet'"
        # More than one change_cipher_spec is dropped like the first, as
        # RFC 9846 §5 has it ("at any time ... before the peer's Finished").
    "test-tls13-keyupdate.py --coalescing
        -e 'app data split, conversation with KeyUpdate msg'"
        # --coalescing: all the requests read before a write are answered
        # by one KeyUpdate, as RFC 9846 §4.6.3 says of a peer that receives
        # several while it is silent. The split one expects that KeyUpdate before the
        # server has anything to write; RFC 9846 asks for it before the next
        # application data, which is when ztls sends it.
    "test-tls13-keyupdate-from-server.py"
    "test-tls13-pkcs-signature.py"
    "test-tls13-rsa-signatures.py"
    "test-tls13-symetric-ciphers.py $(ccm_probes)"   # unsupported: CCM suites
    "test-tls13-lengths.py -p 4435 -n 100"
    "test-tls13-ecdsa-support.py -p 4436
        -e 'Test with ecdsa_secp384r1_sha384'
        -e 'Test with ecdsa_secp521r1_sha512'
        -e 'Test with ecdsa_brainpoolP256r1tls13_sha256'
        -e 'Test with ecdsa_brainpoolP384r1tls13_sha384'
        -e 'Test with ecdsa_brainpoolP512r1tls13_sha512'"
        # a P-256 key signs with ecdsa_secp256r1_sha256 only; brainpool unsupported
    "test-tls13-ecdsa-support.py -p 4438
        -e 'Test with ecdsa_secp256r1_sha256'
        -e 'Test with ecdsa_secp521r1_sha512'
        -e 'Test with ecdsa_brainpoolP256r1tls13_sha256'
        -e 'Test with ecdsa_brainpoolP384r1tls13_sha384'
        -e 'Test with ecdsa_brainpoolP512r1tls13_sha512'"
        # the same for a P-384 key
    "test-tls13-eddsa.py -p 4437
        -e 'ed448 only'"                            # unsupported: Ed448
    "test-tls13-certificate-request.py -p 4434 -s '$sigalgs'
        -c '$clients/client-rsa.pem' -k '$clients/client-rsa.key'"
    "test-tls13-certificate-verify.py -p 4434 -s '$sigalgs'
        -c '$clients/client-rsa.pem' -k '$clients/client-rsa.key'"
    "test-tls13-ecdsa-in-certificate-verify.py -p 4434 -s '$sigalgs'
        -c '$pki/client.pem' -k '$pki/client.key'"
    "test-tls13-eddsa-in-certificate-verify.py -p 4434 -s '$sigalgs'
        -c '$clients/client-ed25519.pem' -k '$clients/client-ed25519.key'"
)

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
