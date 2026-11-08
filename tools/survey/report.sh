#!/usr/bin/env bash
# Summarises a survey: what servers offer (openssl), how ztls fared, and
# the hosts that have TLS 1.3 but failed with ztls, which are our bugs.
# Usage: report.sh OPENSSL_TSV ZTLS_TSV
set -eu
o=$1
z=$2
pct() { awk -F'\t' -v col="$1" '{ c[$col]++; n++ } END { for (k in c) printf "  %-32s %6d  %5.1f%%\n", k, c[k], 100 * c[k] / n }' | sort -k2 -nr; }

echo "== Server support (openssl), $(wc -l <"$o") hosts"
pct 2 <"$o"
echo
echo "== ztls, $(wc -l <"$z") hosts (ok = handshake done, whatever HTTP did)"
pct 2 <"$z"
echo
echo "== Headline, over the hosts that answered either probe"
echo "   TLS 1.3: openssl negotiated it or ztls connected. TLS 1.2 only: openssl"
echo "   negotiated 1.2 and ztls was refused, or ztls alone got a 1.2 answer."
awk -F'\t' 'NR == FNR { o[$1] = $2; next }
    {
        z = ($2 == "ok") ? "ok" : $3
        if (o[$1] == "tls13" || z == "ok") k = "TLS 1.3"
        else if (o[$1] == "tls12_only" || z == "TlsAlertProtocolVersion" || z == "TlsAlertHandshakeFailure") k = "TLS 1.2 only"
        else next
        c[k]++; n++
    }
    END { for (k in c) printf "  %-32s %6d  %5.1f%%\n", k, c[k], 100 * c[k] / n; printf "  %-32s %6d\n", "answered", n }' "$o" "$z" | sort -k2 -nr
echo
echo "== ztls results on hosts that offer TLS 1.3"
awk -F'\t' 'NR == FNR { if ($2 == "tls13") t[$1] = 1; next } ($1 in t) { c[$2 == "ok" ? "ok" : $3]++; n++ }
    END { for (k in c) printf "  %-32s %6d  %5.1f%%\n", k, c[k], 100 * c[k] / n }' "$o" "$z" | sort -k2 -nr
echo
echo "== HTTP after a good handshake"
awk -F'	' '$2 == "ok" { c[$9 ~ /^HTTP\// ? "response" : "none: " $9]++ } END { for (k in c) printf "  %-40s %6d
", k, c[k] }' "$z" | sort -k2 -nr
echo
echo "== TLS 1.3 hosts that failed with ztls (first 5 per error, with openssl's verification)"
awk -F'\t' 'NR == FNR { if ($2 == "tls13") t[$1] = $4; next } ($1 in t) && $2 == "fail" { if (shown[$3]++ < 5) printf "  %-28s %-40s openssl: %s\n", $3, $1, t[$1] }' "$o" "$z" | sort
echo
echo "== Certificate verdicts on TLS 1.3 hosts: ztls vs openssl"
awk -F'\t' 'NR == FNR { if ($2 == "tls13") v[$1] = ($4 == "OK" ? "openssl ok" : "openssl rejects"); next }
    ($1 in v) { zt = ($2 == "ok") ? "ztls ok" : ($3 ~ /^Certificate/ ? "ztls rejects cert" : "ztls other failure"); c[zt "  /  " v[$1]]++ }
    END { for (k in c) printf "  %6d  %s\n", c[k], k }' "$o" "$z" | sort -nr
echo
echo "== What ztls negotiated (suite, group, peer key, scheme, ALPN), top 20"
awk -F'\t' '$2 == "ok" { c[$3 "  " $4 "  " $6 "  " $7 "  " $8]++ } END { for (k in c) printf "  %6d  %s\n", c[k], k }' "$z" | sort -nr | awk 'NR <= 20'
echo
echo "== Hosts that ztls reached but openssl could not with TLS 1.3, first 20"
awk -F'\t' 'NR == FNR { if ($2 != "tls13") t[$1] = $2; next } ($1 in t) && $2 == "ok" { if (n++ < 20) printf "  %-32s %s\n", $1, t[$1] }' "$o" "$z"
