#!/usr/bin/env bash
# Summarises a survey: what servers offer (openssl), how ztls fared, and
# the hosts that have TLS 1.3 but failed with ztls, which are our bugs.
# Usage: report.sh OPENSSL_TSV ZTLS_TSV
set -euo pipefail
o=$1
z=$2
echo "== Server support (openssl), $(wc -l <"$o") hosts"
awk -F'\t' '{ c[$2]++; n++ } END { for (k in c) printf "  %-12s %6d  %5.1f%%\n", k, c[k], 100 * c[k] / n }' "$o" | sort -k2 -nr
echo
echo "== ztls, $(wc -l <"$z") hosts"
awk -F'\t' '{ c[$2]++; n++ } END { for (k in c) printf "  %-12s %6d  %5.1f%%\n", k, c[k], 100 * c[k] / n }' "$z" | sort -k2 -nr
echo
echo "== ztls results on hosts that offer TLS 1.3"
awk -F'\t' 'NR == FNR { if ($2 == "tls13") t[$1] = 1; next } ($1 in t) { c[$2 == "ok" ? "ok" : $3]++; n++ }
    END { for (k in c) printf "  %-32s %6d  %5.1f%%\n", k, c[k], 100 * c[k] / n }' "$o" "$z" | sort -k2 -nr
echo
echo "== TLS 1.3 hosts that failed with ztls (first 5 per error, with openssl's verification)"
awk -F'\t' 'NR == FNR { if ($2 == "tls13") t[$1] = $4; next } ($1 in t) && $2 == "fail" { if (shown[$3]++ < 5) printf "  %-28s %-40s openssl: %s\n", $3, $1, t[$1] }' "$o" "$z" | sort
echo
echo "== Certificate verdicts on TLS 1.3 hosts: ztls vs openssl"
awk -F'\t' 'NR == FNR { if ($2 == "tls13") v[$1] = ($4 == "OK" ? "openssl ok" : "openssl rejects"); next }
    ($1 in v) { zt = ($2 == "ok") ? "ztls ok" : ($3 ~ /^Certificate/ ? "ztls rejects cert" : "ztls other failure"); c[zt "  /  " v[$1]]++ }
    END { for (k in c) printf "  %6d  %s\n", c[k], k }' "$o" "$z" | sort -nr
echo
echo "== What ztls negotiated (suite, group, peer key, scheme, ALPN)"
awk -F'\t' '$2 == "ok" { c[$3 "  " $4 "  " $6 "  " $7 "  " $8]++ } END { for (k in c) printf "  %6d  %s\n", c[k], k }' "$z" | sort -nr | head -20
echo
echo "== Hosts that ztls reached but openssl could not with TLS 1.3"
awk -F'\t' 'NR == FNR { if ($2 != "tls13") t[$1] = $2; next } ($1 in t) && $2 == "ok" { printf "  %-32s %s\n", $1, t[$1] }' "$o" "$z" | head -20
