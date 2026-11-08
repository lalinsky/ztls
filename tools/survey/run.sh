#!/usr/bin/env bash
# The whole survey: fetch hosts, probe with openssl and with ztls, report.
# Usage: run.sh, with the selection in the environment:
#   TOP=10000                 the top 10000 (default)
#   TOP=1000000 SAMPLE=5000   5000 drawn at random from the whole list,
#   SEED=ztls                 repeatably
#   PARALLEL=50               connections at a time
# Results land in tools/survey/out/<date>-<selection>/. Needs curl,
# openssl 1.1.1+, shuf and zig.
set -euo pipefail
cd "$(dirname "$0")/../.."
: "${TOP:=10000}"
: "${SAMPLE:=}"
: "${SEED:=ztls}"
: "${PARALLEL:=50}"
: "${ZIG:=zig}"
name=top$TOP${SAMPLE:+-sample$SAMPLE-$SEED}
out=tools/survey/out/$(date +%Y%m%d)-$name
mkdir -p "$out"

"$ZIG" build survey-probe -Doptimize=ReleaseSafe
TOP=$TOP SAMPLE=$SAMPLE SEED=$SEED tools/survey/fetch_hosts.sh "$out/hosts.txt" tools/survey/out
tools/survey/probe_openssl.sh "$out/hosts.txt" "$out/openssl.tsv" "$PARALLEL"
PROBE=$PWD/zig-out/bin/survey-probe tools/survey/probe_ztls.sh "$out/hosts.txt" "$out/ztls.tsv" "$PARALLEL"
tools/survey/report.sh "$out/openssl.tsv" "$out/ztls.tsv" | tee "$out/report.txt"
