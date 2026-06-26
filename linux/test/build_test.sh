#!/usr/bin/env bash
# Compile the test host/mock/engine binaries. Two arch modes:
#   build_test.sh native    -> host-arch binaries (run directly)
#   build_test.sh x64        -> x86-64 binaries + an x86-64 libfragment.so, for
#                               running the portable subset under qemu-x86_64
# The full real-libcurl matrix only runs in 'native' (it needs the system
# libcurl); the x64 subset is the engine unit test + the self-contained mock
# interposition + static-inline-hook tests, which need no real libcurl.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(dirname "$HERE")"
MODE="${1:-native}"

if [ "$MODE" = "x64" ]; then
    CC="${CROSS_CC:-x86_64-linux-gnu-gcc}"
    OUT="$ROOT/build/x64"
    BP=""
else
    CC="${CC:-cc}"
    OUT="$ROOT/build"
    case "$(uname -m)" in aarch64|arm64) BP="-mbranch-protection=standard" ;; *) BP="" ;; esac
fi
mkdir -p "$OUT"
# -Wall but not -Wunused-function: the engine/logger are header-only, so a test
# that uses a subset of the API legitimately leaves some statics unreferenced
# (the Windows build's /W3 likewise does not flag these).
W="-O2 -std=c17 -Wall -Wno-unused-function"

echo "== build_test ($MODE) with $CC -> $OUT =="

# Engine unit test (no curl, no servers).
$CC $W $BP "$HERE/hooktest.c" -o "$OUT/hooktest" -lpthread

# Self-contained mock libcurl + its interposition host (no real libcurl).
$CC $W -fPIC -shared "$HERE/mockcurl.c" -o "$OUT/libmockcurl.so"
$CC $W "$HERE/host_mock.c" -o "$OUT/host_mock" -L"$OUT" -lmockcurl -Wl,-rpath,"$OUT"

# Static-curl path: embed the mock so curl_easy_setopt is a .symtab-only symbol
# (no dynamic export), which forces the inline-hook sweep. -no-pie keeps the call
# direct (not a preemptible PLT entry), exactly like a statically-linked curl.
$CC $W -no-pie "$HERE/host_mock.c" "$HERE/mockcurl.c" -o "$OUT/host_mock_static"

if [ "$MODE" = "x64" ]; then
    # Cross-build libfragment.so for x86-64 so the qemu subset can preload it.
    $CC $W -fPIC -fvisibility=hidden -shared "$ROOT/main.c" \
        -o "$OUT/libfragment.so" -ldl -lpthread -Wl,-z,nodelete
    echo "== x64 test binaries built in $OUT =="
    exit 0
fi

# ---- native-only: the real-libcurl hosts (need -lcurl) --------------------
if echo 'int main(void){return 0;}' | $CC -xc - -lcurl -o /dev/null 2>/dev/null; then
    $CC $W "$HERE/host.c"        -o "$OUT/host"        -lcurl -ldl
    $CC $W "$HERE/host_urlapi.c" -o "$OUT/host_urlapi" -lcurl
    $CC $W "$HERE/host_stress.c" -o "$OUT/host_stress" -lcurl -lpthread
    $CC $W "$HERE/host_bench.c"  -o "$OUT/host_bench"  -lcurl
    $CC $W "$HERE/host_plugin.c" -o "$OUT/host_plugin" -ldl
    $CC $W -fPIC -shared "$HERE/plugin.c" -o "$OUT/libplugin.so" -lcurl
else
    echo "  (no -lcurl: skipping the real-libcurl hosts; mock + engine still built)"
fi

echo "== native test binaries built in $OUT =="
