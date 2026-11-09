#!/usr/bin/env bash
# Runs BoringSSL's TLS test runner (BoGo) against ztls.
#
# Needs Go and a BoringSSL checkout. BORINGSSL points at one; without it,
# a shallow clone is made under .bogo/ in the repository and reused.
# Extra arguments go to the runner, e.g. -test "Basic-Client-TLS13*".
set -euo pipefail
cd "$(dirname "$0")/../.."

: "${ZIG:=zig}"
: "${BORINGSSL:=.bogo/boringssl}"
# Pinned: the runner's tests change, and so would the counts below.
: "${BORINGSSL_REV:=0131ae9d78e42fcc2c1811315e62410ad96d8230}"
# Passes with the pinned runner; fewer means tests slipped from passing to
# unimplemented or failed, which -allow-unimplemented alone would hide.
: "${MIN_PASS:=552}"

# Only the pinned commit is fetched; the full history is 400 MB.
if [ ! -d "$BORINGSSL" ]; then
    git init -q "$BORINGSSL"
    git -C "$BORINGSSL" remote add origin https://boringssl.googlesource.com/boringssl
fi
if [ "$(git -C "$BORINGSSL" rev-parse --verify -q HEAD)" != "$BORINGSSL_REV" ]; then
    git -C "$BORINGSSL" fetch -q --depth 1 origin "$BORINGSSL_REV"
    git -C "$BORINGSSL" checkout -q "$BORINGSSL_REV"
fi

"$ZIG" build bogo-shim
shim="$PWD/zig-out/bin/bogo-shim"
config="$PWD/tests/bogo/config.json"

cd "$BORINGSSL/ssl/test/runner"
output=$(mktemp)
trap 'rm -f "$output"' EXIT
# In an `if`, a failing pipeline does not end the script under `set -e`.
if go test -shim-path "$shim" -shim-config "$config" -allow-unimplemented -pipe "$@" | tee "$output"; then
    status=0
else
    status=${PIPESTATUS[0]}
fi
passed=$(grep -c '^PASSED (' "$output" || true)
if [ $# -eq 0 ] && [ "$passed" -lt "$MIN_PASS" ]; then
    echo "only $passed tests passed, expected at least $MIN_PASS" >&2
    exit 1
fi
exit "$status"
