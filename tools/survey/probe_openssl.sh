#!/usr/bin/env bash
# Asks each host for TLS 1.3 with openssl s_client, and the ones that
# refuse for TLS 1.2, to tell what the server offers without ztls in the
# picture. Usage: probe_openssl.sh HOSTS_FILE OUT_TSV [PARALLEL]
# Output: HOST<TAB>tls13|tls12_only|unreachable<TAB>CIPHERSUITE<TAB>VERIFICATION
# (the last as openssl reports it against the system roots and the host
# name, or the error for an unreachable host). The TLS 1.3 attempt is
# made twice before a host is taken to lack it.
set -euo pipefail
: "${TIMEOUT:=15}"

attempt() {
    local h=$1 version=$2
    timeout "$TIMEOUT" openssl s_client -connect "$h:443" -servername "$h" -verify_hostname "$h" "$version" -brief </dev/null 2>&1
}

established() {
    local h=$1 class=$2 r=$3
    printf '%s\t%s\t%s\t%s\n' "$h" "$class" "$(sed -n 's/^Ciphersuite: //p' <<<"$r" | head -1)" \
        "$(sed -n 's/^Verification[: ]*//p' <<<"$r" | head -1 | tr -d '\r')"
}

one() {
    local h=$1 r try
    for try in 1 2; do
        if r=$(attempt "$h" -tls1_3) && grep -q '^CONNECTION ESTABLISHED' <<<"$r"; then
            established "$h" tls13 "$r"
            return
        fi
        [ "$try" -eq 1 ] && sleep 1
    done
    if r=$(attempt "$h" -tls1_2) && grep -q '^CONNECTION ESTABLISHED' <<<"$r"; then
        established "$h" tls12_only "$r"
    else
        printf '%s\tunreachable\t-\t%s\n' "$h" "$(grep -m1 -iE 'error|alert|refused|timed out|resolve|unable' <<<"$r" | tr -d '\r' | cut -c1-120)"
    fi
}
if [ "${1:-}" = "--one" ]; then one "$2"; exit 0; fi

hosts=$1
out=$2
parallel=${3:-50}
: >"$out"
TIMEOUT=$TIMEOUT xargs -a "$hosts" -P "$parallel" -I{} "$0" --one {} >>"$out"
echo "$(wc -l <"$out") results in $out"
