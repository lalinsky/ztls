#!/usr/bin/env bash
# Writes hosts from the Chrome UX Report's public top list of a million
# origins (github.com/zakird/crux-top-lists; ranks come in buckets of
# 1000, 5000, 10000, ...). Usage: fetch_hosts.sh OUT_FILE [CACHE_DIR]
#   TOP=N      hosts ranked N or better (default: the whole list)
#   SAMPLE=K   K hosts drawn at random from those, with SEED (default
#              "ztls") making the draw repeatable
set -euo pipefail
out=$1
cache=${2:-$(dirname "$out")}
: "${TOP:=1000000}"
: "${SAMPLE:=}"
: "${SEED:=ztls}"
list=$cache/crux-current.csv.gz
if [ ! -s "$list" ]; then
    curl -fsSL -o "$list" https://raw.githubusercontent.com/zakird/crux-top-lists/main/data/global/current.csv.gz
fi
# origin,rank; https origins only, scheme and any port stripped, first
# occurrence of a host kept.
hosts() {
    gzip -dc "$list" | awk -F, -v n="$TOP" '
        NR > 1 && $2 + 0 <= n && $1 ~ /^https:\/\// {
            host = substr($1, 9); sub(/:[0-9]+$/, "", host)
            if (!(host in seen)) { seen[host] = 1; print host }
        }'
}
if [ -n "$SAMPLE" ]; then
    # A keyed stream as shuf's randomness makes the draw a function of SEED.
    hosts | shuf -n "$SAMPLE" --random-source=<(openssl enc -aes-256-ctr -pass "pass:$SEED" -nosalt -pbkdf2 </dev/zero 2>/dev/null) >"$out"
else
    hosts >"$out"
fi
echo "$(wc -l <"$out") hosts in $out"
