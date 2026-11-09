#!/usr/bin/env bash
# Connects to each host with ztls (see probe.zig), one process per host.
# Usage: probe_ztls.sh HOSTS_FILE OUT_TSV [PARALLEL]
#   PROBE         the built survey-probe binary
#   PROBE_GROUPS  passed as --groups, e.g. x25519 to leave out ML-KEM
#   PROBE_TLS12   set to 1 to offer TLS 1.2 as well (--tls12)
#   TIMEOUT       seconds per host; a handshake that finished in time but
#                 got no HTTP response is reported with STATUS "Timeout"
# Name lookups that fail are retried, since a local resolver stub falls
# over under many parallel lookups.
set -euo pipefail
: "${TIMEOUT:=20}"
: "${PROBE:=$(dirname "$0")/../../zig-out/bin/survey-probe}"
: "${PROBE_GROUPS:=}"
: "${PROBE_TLS12:=}"

one() {
    local h=$1 r status attempt
    for attempt in 1 2 3; do
        r=$(timeout "$TIMEOUT" "$PROBE" "$h" ${PROBE_GROUPS:+--groups "$PROBE_GROUPS"} ${PROBE_TLS12:+--tls12} 2>&1) && status=0 || status=$?
        case "$r" in
            *"	fail	UnknownHostName" | *"	fail	NetworkUnreachable") [ "$attempt" -lt 3 ] && { sleep 2; continue; } ;;
        esac
        break
    done
    if [ "$status" -eq 124 ] && [ -n "$r" ]; then
        printf '%s\n' "$r" | tail -1 | awk -F'\t' -v OFS='\t' '{ if (NF == 9) $9 = "Timeout"; print }'
    elif [ "$status" -eq 124 ]; then
        printf '%s\tfail\tTimeout\n' "$h"
    elif [ -z "$r" ]; then
        printf '%s\tfail\tExit%s\n' "$h" "$status"
    else
        printf '%s\n' "$r" | tail -1
    fi
}
if [ "${1:-}" = "--one" ]; then one "$2"; exit 0; fi

hosts=$1
out=$2
parallel=${3:-50}
: >"$out"
PROBE=$PROBE PROBE_GROUPS=$PROBE_GROUPS PROBE_TLS12=$PROBE_TLS12 TIMEOUT=$TIMEOUT xargs -a "$hosts" -P "$parallel" -I{} "$0" --one {} >>"$out"
echo "$(wc -l <"$out") results in $out"
