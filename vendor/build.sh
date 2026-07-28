#!/bin/bash
# Build the narrow py9p native codec from plan9port's 9P wire converters.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
P9="$HERE/plan9port"
INC="$P9/include"
SRC="$P9/src/lib9"
WRAP="$HERE/py9p_c"

OUT="$HERE/build"
SO_NAME="libpy9p.so"
SAN_FLAGS=()
if [ "${SANITIZE:-0}" = "1" ]; then
    OUT="$HERE/build-asan"
    SO_NAME="libpy9p-asan.so"
    SAN_FLAGS=(-fsanitize=address,undefined -fno-omit-frame-pointer -g)
    echo "=== SANITIZER BUILD (address,undefined) -> $SO_NAME ==="
fi

mkdir -p "$OUT"
CC_BIN="${CC:-gcc}"
CFLAGS=(-DPLAN9PORT -DNOPLAN9DEFINES -I"$INC" -I"$WRAP" -O2 -fPIC -Wall -Wextra -Wno-unused-parameter "${SAN_FLAGS[@]}")

compile() {
    local src="$1"
    local obj="$OUT/$(basename "$src" .c).o"
    echo "CC $src"
    "$CC_BIN" "${CFLAGS[@]}" -c -o "$obj" "$src"
}

compile "$SRC/convM2S.c"
compile "$SRC/convS2M.c"
compile "$SRC/convM2D.c"
compile "$SRC/convD2M.c"
compile "$WRAP/py9p.c"

LINK_EXTRA=(-Wl,--no-undefined)
if [ "${SANITIZE:-0}" = "1" ]; then
    LINK_EXTRA=()
fi

echo "LD $SO_NAME"
"$CC_BIN" -shared -fPIC "${SAN_FLAGS[@]}" -o "$HERE/$SO_NAME" "$OUT"/*.o "${LINK_EXTRA[@]}"
ls -la "$HERE/$SO_NAME"
