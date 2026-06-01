#!/usr/bin/env bash
set -euo pipefail

KEYLEN=48
KEYHEX=$(openssl rand -hex ${KEYLEN})
export KEYHEX

python3 - <<'PY' > secret_parts.h
import os
keyhex = os.environ["KEYHEX"]
key = bytes.fromhex(keyhex)

# split into two arrays
mid = len(key)//2
part_a = key[:mid]
part_b = key[mid:]

def emit(name, data):
    print(f"unsigned char {name}[] = {{", end="")
    print(", ".join(f"0x{b:02x}" for b in data), end="")
    print("};")

print("/* auto-generated secret_parts.h */")
print("#ifndef SECRET_PARTS_H")
print("#define SECRET_PARTS_H")
emit("part_a", part_a)
emit("part_b", part_b)
print("#endif")
PY

# =========================
# Build, extract symbols, strip
# =========================

gcc -o vaultd.unstripped vaultd.c -fPIE -pie -O2 -g -Wl,-z,relro,-z,now
nm -C --defined-only vaultd.unstripped > nm_out.txt

: > symbols.txt
awk '{
  addr=$1; gsub(/^0x/,"",addr);
  if($0 ~ / dummy_handler$/)        printf("dummy_handler:0x%s\n", addr);
  if($0 ~ / reveal_runtime_token$/) printf("reveal_runtime_token:0x%s\n", addr);
  if($0 ~ / secret_key_storage$/)   printf("secret_key_storage:0x%s\n", addr);
  if($0 ~ / reveal_token2$/)        printf("reveal_token2:0x%s\n", addr);
}' nm_out.txt >> symbols.txt

# Deterministic overflow distance: names[8][0x200] -> 8 * 0x200 bytes, then htable
printf "overflow_offset:0x%lx\n" $(( 8 * 0x200 )) >> symbols.txt

mv vaultd.unstripped vaultd
strip -s vaultd || true

# Build artifacts (not needed at runtime)
rm -f nm_out.txt

echo "[+] Build complete"
echo "[+] symbols.txt:"; cat symbols.txt