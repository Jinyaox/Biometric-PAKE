#!/usr/bin/env bash
# build.sh — compile precomp_scalarmult.c with configurable window size
#
# Usage:
#   bash build.sh          # default w=4
#   bash build.sh 3        # w=3, 96KB table, fits Apple M L1 cache
#   bash build.sh 5        # w=5, 251KB table
#   bash build.sh 6        # w=6, 433KB table
set -e

WINDOW_BITS=${1:-8}   # default to 8 if no argument given
echo "Building with WINDOW_BITS=${WINDOW_BITS}..."

if command -v pkg-config &>/dev/null && pkg-config --exists libsodium 2>/dev/null; then
    VERSION=$(pkg-config --modversion libsodium 2>/dev/null)
else
    VERSION=$(brew list --versions libsodium 2>/dev/null | awk '{print $2}')
fi

SRC_DIR="libsodium-src"
TARBALL="libsodium-${VERSION}.tar.gz"
URL="https://download.libsodium.org/libsodium/releases/${TARBALL}"

if [ ! -d "$SRC_DIR" ]; then
    curl -L -o "$TARBALL" "$URL" 2>/dev/null
    mkdir -p "$SRC_DIR"
    tar xf "$TARBALL" --strip-components=1 -C "$SRC_DIR"
    rm "$TARBALL"
fi

SODIUM_CFLAGS=$(pkg-config --cflags libsodium 2>/dev/null || \
                echo "-I$(brew --prefix libsodium)/include")

INTERNAL_INC="-I${SRC_DIR}/src/libsodium/include \
              -I${SRC_DIR}/src/libsodium/include/sodium \
              -I${SRC_DIR}/src/libsodium/include/sodium/private"

STATIC_LIB="${SRC_DIR}/src/libsodium/.libs/libsodium.a"

OMP_PREFIX=$(brew --prefix libomp)
SODIUM_PREFIX=$(brew --prefix libsodium)

for w in 4 8; do
    cc -O2 -w -fPIC -shared \
       -DWINDOW_BITS=$w \
       -I${SODIUM_PREFIX}/include \
       -I libsodium-src/src/libsodium/include \
       -I libsodium-src/src/libsodium/include/sodium \
       -I libsodium-src/src/libsodium/include/sodium/private \
       -Xpreprocessor -fopenmp \
       -I${OMP_PREFIX}/include \
       precomp_scalarmult.c \
       libsodium-src/src/libsodium/.libs/libsodium.a \
       ${OMP_PREFIX}/lib/libomp.dylib \
       -o _precomp_scalarmult_w${w}.so
    echo "Built w=${w}: $(ls -lah _precomp_scalarmult_w${w}.so | awk '{print $5}')"
done

# Build the default library with the user-selected (or default) WINDOW_BITS
cc -O2 -w -fPIC -shared \
   -DWINDOW_BITS=${WINDOW_BITS} \
   -I${SODIUM_PREFIX}/include \
   -I libsodium-src/src/libsodium/include \
   -I libsodium-src/src/libsodium/include/sodium \
   -I libsodium-src/src/libsodium/include/sodium/private \
   -Xpreprocessor -fopenmp \
   -I${OMP_PREFIX}/include \
   precomp_scalarmult.c \
   libsodium-src/src/libsodium/.libs/libsodium.a \
   ${OMP_PREFIX}/lib/libomp.dylib \
   -o _precomp_scalarmult.so

echo "✓ Built _precomp_scalarmult.so (w=${WINDOW_BITS})"