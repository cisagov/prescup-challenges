#!/usr/bin/env sh
set -eu

# 1) Ensure TOKEN2 exists at runtime (platform-provided or generate)
if [ -z "${TOKEN2:-}" ]; then
  TOKEN2="PCCC{$(head -c 64 /dev/urandom | tr -dc 'A-Z0-9' | head -c 4)-$(head -c 64 /dev/urandom | tr -dc '0-9' | head -c 4)}"
fi
export TOKEN2

# 2) Build-time obfuscation so token isn't "strings"-visible:
# Generate a random per-container XOR key and XOR-encrypt the token into a C header.
KEY="$(head -c 1 /dev/urandom | od -An -tu1 | tr -d ' ')"
[ -n "$KEY" ] || KEY=93

# Write encrypted bytes into header
python3 - <<PY
import os
token=os.environ["TOKEN2"].encode()
key=int(os.environ.get("KEY","93"))
ct=[b ^ key for b in token]
print("#pragma once")
print(f"#define TOKEN2_XOR_KEY {key}")
print("static const unsigned char TOKEN2_CT[] = {" + ",".join(hex(x) for x in ct) + "};")
print(f"static const unsigned int TOKEN2_CT_LEN = {len(ct)};")
PY > /tmp/token2_blob.h

# 3) Compile at runtime, embedding only ciphertext + key (not plaintext)
gcc -O2 -fno-stack-protector -z execstack -no-pie -std=c11 \
  -include /tmp/token2_blob.h \
  /var/www/html/code_osiris_v2.c -o /var/www/html/code_osiris_v2

# 4) Run apache
exec apache2ctl -D FOREGROUND
