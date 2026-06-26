#!/usr/bin/env bash
# Build libfragment.so + the fragment loader with whatever toolchain is present.
# Prefers CMake (Ninja if available), and falls back to a direct cc build so a
# bare box with only a C compiler still works. No hardcoded paths.
# Usage: build.sh [Debug|Release]
set -euo pipefail

CFG="${1:-Release}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD="$HERE/build"

# The release workflow exports FRAGMENT_VERSION=<git tag>; otherwise the
# in-development default in common/version.h is used.
VER=()
[ -n "${FRAGMENT_VERSION:-}" ] && VER=(-DFRAGMENT_VERSION="$FRAGMENT_VERSION")

if command -v cmake >/dev/null 2>&1; then
    GEN=()
    command -v ninja >/dev/null 2>&1 && GEN=(-G Ninja)
    cmake -S "$HERE" -B "$BUILD" "${GEN[@]}" -DCMAKE_BUILD_TYPE="$CFG" "${VER[@]}"
    cmake --build "$BUILD" --config "$CFG"
    echo
    echo "=== Build OK -- artifacts in $BUILD (libfragment.so, fragment) ==="
    exit 0
fi

# --- CMake-less fallback ----------------------------------------------------
CC="${CC:-cc}"
mkdir -p "$BUILD"
OPT="-O2"; [ "$CFG" = "Debug" ] && OPT="-O0 -g -DDEBUG"
EXTRA=""
case "$(uname -m)" in
    aarch64|arm64) EXTRA="-mbranch-protection=standard" ;;
esac
VDEF=()
[ -n "${FRAGMENT_VERSION:-}" ] && VDEF=(-DFRAGMENT_VERSION="\"$FRAGMENT_VERSION\"")
echo "cc fallback: $CC $OPT"
"$CC" $OPT -std=c17 -fPIC -fvisibility=hidden $EXTRA "${VDEF[@]}" -shared \
    "$HERE/main.c" -o "$BUILD/libfragment.so" -ldl -lpthread -Wl,-z,nodelete
"$CC" $OPT -std=c17 "${VDEF[@]}" "$HERE/tools/fragment.c" -o "$BUILD/fragment" -ldl
echo
echo "=== Build OK -- artifacts in $BUILD (libfragment.so, fragment) ==="
