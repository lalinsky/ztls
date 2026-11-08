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
: "${BORINGSSL_REV:=main}"

if [ ! -d "$BORINGSSL" ]; then
    mkdir -p "$(dirname "$BORINGSSL")"
    git clone --depth 1 --branch "$BORINGSSL_REV" https://boringssl.googlesource.com/boringssl "$BORINGSSL"
fi

"$ZIG" build bogo-shim
shim="$PWD/zig-out/bin/bogo-shim"
config="$PWD/tests/bogo/config.json"

cd "$BORINGSSL/ssl/test/runner"
exec go test -shim-path "$shim" -shim-config "$config" -allow-unimplemented -pipe "$@"
