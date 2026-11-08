#!/usr/bin/env bash
# Connects to each host with ztls (see probe.zig), one process per host.
# Usage: probe_ztls.sh HOSTS_FILE OUT_TSV [PARALLEL]; PROBE points at the
# built survey-probe binary.
set -euo pipefail
: "${TIMEOUT:=20}"
: "${PROBE:=$(dirname "$0")/../../zig-out/bin/survey-probe}"

one() {
    local h=$1 r status
    r=$(timeout "$TIMEOUT" "$PROBE" "$h" 2>&1) && status=0 || status=$?
    if [ "$status" -eq 124 ]; then
        printf '%s\tfail\tTimeout\n' "$h"
    elif [ -z "$r" ]; then
        printf '%s\tfail\tExit%s\n' "$h" "$status"
    else
        printf '%s\n' "$r" | head -1
    fi
}
if [ "${1:-}" = "--one" ]; then one "$2"; exit 0; fi

hosts=$1
out=$2
parallel=${3:-50}
: >"$out"
PROBE=$PROBE TIMEOUT=$TIMEOUT xargs -a "$hosts" -P "$parallel" -I{} "$0" --one {} >>"$out"
echo "$(wc -l <"$out") results in $out"
