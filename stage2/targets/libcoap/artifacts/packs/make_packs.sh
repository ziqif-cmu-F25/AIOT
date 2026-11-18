#!/usr/bin/env bash
# Regenerate the C0 file packs + file tree from YOUR own libcoap checkout
# (affected commit 7cf7465b784baded4de183290c547d582becfd28 / v4.3.5).
# Usage:  ./make_packs.sh /path/to/libcoap   (dir that contains src/ and include/)
set -euo pipefail
SRC="${1:?usage: make_packs.sh /path/to/libcoap_checkout}"
OUT="$(cd "$(dirname "$0")" && pwd)"

build() { local out="$1"; shift; : > "$out"
  for f in "$@"; do
    printf '==== src/%s ====\n' "$f" >> "$out"
    cat "$SRC/src/$f" >> "$out"
    printf '\n\n' >> "$out"
  done
}
# true file = coap_address.c ; caller = coap_proxy.c ; decoys = uri/option/pdu/encode
build "$OUT/c0_pack_1.txt" coap_option.c coap_uri.c coap_address.c coap_encode.c coap_proxy.c coap_pdu.c
build "$OUT/c0_pack_2.txt" coap_pdu.c coap_proxy.c coap_encode.c coap_address.c coap_uri.c coap_option.c
( cd "$SRC" && ls src/*.c include/coap3/*.h 2>/dev/null | sort ) > "$OUT/filetree.txt"
echo "wrote c0_pack_1.txt, c0_pack_2.txt, filetree.txt in $OUT"
