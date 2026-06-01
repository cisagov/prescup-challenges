#!/usr/bin/env bash
set -euo pipefail

cd /opt/ctf

# Ensure env-backed artifacts exist.
# The secret-file token is stored in token_secret_file.enc, encrypted with the
# recovered key (hex) derived from secret_parts.h.

PUB_TOKEN="${publictoken:?publictoken env var must be set}"
SECRET_TOKEN="${secrettoken:?secrettoken env var must be set}"

# Keep a plaintext copy of the public token (optional convenience for operators)
echo -n "$PUB_TOKEN" > token_public.txt

# Parse secret_parts.h to reconstruct the key bytes, then encrypt secrettoken.
SECRET_KEY_HEX=$(python3 - <<'PY'
import re
with open('secret_parts.h','r',encoding='utf-8',errors='ignore') as f:
    txt=f.read()

def parse_array(name):
    m=re.search(rf"{name}\s*\[\]\s*=\s*\{{([^}}]+)\}};", txt, re.S)
    if not m:
        return []
    return [int(x,16) for x in re.findall(r"0x([0-9a-fA-F]{2})", m.group(1))]

a=parse_array('part_a')
b=parse_array('part_b')
key=bytes(a+b)
print(key.hex())
PY
)

# Always regenerate to match the runtime env.
rm -f token_secret_file.enc token_plain.txt 2>/dev/null || true
printf "%s" "$SECRET_TOKEN" > token_plain.txt
openssl enc -aes-128-cbc -salt -pass pass:"${SECRET_KEY_HEX}" -in token_plain.txt -out token_secret_file.enc
rm -f token_plain.txt

exec "$@"