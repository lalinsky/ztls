#!/usr/bin/env bash
# What TLS 1.2-only servers need, for sizing a minimal TLS 1.2 client.
# Each host is asked with openssl s_client -tls1_2: once by default, to
# record what it picks (suite, curve, how it signed the key exchange,
# extended master secret), then with only ECDHE+AEAD suites and with each
# curve alone. Usage: probe_tls12.sh HOSTS_FILE OUT_TSV [PARALLEL]
# Output: HOST SUITE CURVE SIGTYPE SIGDIGEST EMS ECDHE_AEAD X25519 P256 P384
# (yes/no for the last four; "-" where the default handshake failed).
set -euo pipefail
: "${TIMEOUT:=15}"

# Two tries, since a busy host answers one connection and drops the next.
ok() {
    local try
    for try in 1 2; do
        timeout "$TIMEOUT" openssl s_client -connect "$1:443" -servername "$1" -tls1_2 "${@:2}" -brief </dev/null 2>&1 | grep -q '^CONNECTION ESTABLISHED' && { echo yes; return; }
    done
    echo no
}

one() {
    local h=$1 r suite curve sig dig ems
    r=$(timeout "$TIMEOUT" openssl s_client -connect "$h:443" -servername "$h" -tls1_2 </dev/null 2>&1) || true
    if ! grep -q 'Cipher is' <<<"$r" || grep -q 'Cipher is (NONE)' <<<"$r"; then
        printf '%s\t-\t-\t-\t-\t-\t-\t-\t-\t-\n' "$h"
        return
    fi
    suite=$(sed -n 's/.*Cipher is \([^ ]*\).*/\1/p' <<<"$r" | head -1)
    curve=$(sed -n 's/^Server Temp Key: \(ECDH, \)\{0,1\}\([^,]*\),.*/\2/p' <<<"$r" | head -1)
    sig=$(sed -n 's/^Peer signature type: //p' <<<"$r" | head -1)
    dig=$(sed -n 's/^Peer signing digest: //p' <<<"$r" | head -1)
    ems=$(grep -q 'Extended master secret: yes' <<<"$r" && echo yes || echo no)
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$h" "$suite" "${curve:--}" "${sig:--}" "${dig:--}" "$ems" \
        "$(ok "$h" -cipher 'ECDHE+AESGCM:ECDHE+CHACHA20')" \
        "$(ok "$h" -curves X25519)" "$(ok "$h" -curves P-256)" "$(ok "$h" -curves P-384)"
}
if [ "${1:-}" = "--one" ]; then one "$2"; exit 0; fi

hosts=$1
out=$2
parallel=${3:-30}
: >"$out"
TIMEOUT=$TIMEOUT xargs -a "$hosts" -P "$parallel" -I{} "$0" --one {} >>"$out"
echo "$(wc -l <"$out") results in $out"

echo "== default pick: suite"; cut -f2 "$out" | sort | uniq -c | sort -nr | head -12
echo "== default pick: curve / signature / EMS"; awk -F'\t' '$2 != "-" { c[$3 "  " $4 "+" $5 "  ems=" $6]++ } END { for (k in c) printf "  %5d  %s\n", c[k], k }' "$out" | sort -nr | head -12
echo "== key exchange signature the server chose (RSA = PKCS#1 v1.5)"; awk -F'\t' '$2 != "-" { c[$4]++ } END { for (k in c) printf "  %5d  %s\n", c[k], k }' "$out" | sort -nr
echo "== reachable with (of hosts the default reached)"
awk -F'\t' '$2 != "-" { n++; a += ($7 == "yes"); x += ($8 == "yes"); p += ($9 == "yes"); q += ($10 == "yes"); xp += ($8 == "yes" || $9 == "yes"); ax += ($7 == "yes" && ($8 == "yes" || $9 == "yes")) }
    END { printf "  %-40s %5d\n", "reached by default", n; printf "  %-40s %5d  %5.1f%%\n", "ECDHE + AES-GCM/ChaCha20 only", a, 100*a/n; printf "  %-40s %5d  %5.1f%%\n", "X25519 only (also limits ECDSA cert curves)", x, 100*x/n; printf "  %-40s %5d  %5.1f%%\n", "P-256 only", p, 100*p/n; printf "  %-40s %5d  %5.1f%%\n", "X25519 or P-256", xp, 100*xp/n; printf "  %-40s %5d  %5.1f%%\n", "P-384 only", q, 100*q/n; printf "  %-40s %5d  %5.1f%%\n", "AEAD + ECDHE on X25519 or P-256", ax, 100*ax/n }' "$out"
