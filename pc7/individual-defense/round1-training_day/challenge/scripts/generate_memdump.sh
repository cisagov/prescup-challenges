#!/bin/bash
set -euo pipefail

: "${TOKEN2:?TOKEN2 must be set}"

OUT="/challenge/memory_dump.raw"
SIZE_MB=50

# Marker to help locate the blob (doesn't reveal the token)
# Keep it short and non-obvious so "strings" doesn't directly give the answer.
MARKER="LCM2"   # Lancer Challenge Memory v2
VERSION_BYTE="\x02"

echo "[*] Building ${SIZE_MB}MB memory dump at $OUT"
dd if=/dev/urandom of="$OUT" bs=1M count="$SIZE_MB" status=none

# Build plaintext payload: base64("TOKEN2: <token>") with no newline
B64="$(printf 'TOKEN2: %s' "$TOKEN2" | base64 -w0)"

# Random XOR key in [0xA1, 0xFF]
KEY_DEC="$(python3 - <<'PY'
import random
print(random.randint(0xA1, 0xFF))
PY
)"
KEY_HEX="$(printf '0x%02X' "$KEY_DEC")"
echo "[*] XOR key chosen (hidden from solvers): $KEY_HEX"

# XOR the base64 bytes with the key and write a structured blob:
#   MARKER(4) | VERSION(1) | KEY(1) | LEN(2 LE) | XOR_DATA(LEN)
python3 - <<PY
import os, struct, random

out_path = ${OUT@Q}
marker = ${MARKER@Q}.encode("ascii")
ver = 2
key = $KEY_DEC
b64 = ${B64@Q}.encode("ascii")
x = bytes([c ^ key for c in b64])
blob = marker + bytes([ver]) + bytes([key]) + struct.pack("<H", len(x)) + x

# Choose a random offset that keeps blob fully inside the file.
st = os.stat(out_path).st_size
max_off = st - len(blob) - 1
off = random.randint(0, max_off)

with open(out_path, "r+b") as f:
    f.seek(off)
    f.write(blob)

print(f"[*] Embedded blob at offset {off} (len={len(blob)})")
PY

echo "[*] Done: $OUT"

