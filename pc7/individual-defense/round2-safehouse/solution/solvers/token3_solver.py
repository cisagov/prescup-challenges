#!/usr/bin/env python3
import io
import re
import sys
import zipfile
import binascii

HDR = b"SAFEHOUSE_DD3\x00"
KEY_RE = re.compile(br"cmt-k:([0-9a-fA-F]{2})")

def xor_bytes(data: bytes, key: int) -> bytes:
    k = key & 0xFF
    return bytes(b ^ k for b in data)

def extract_key_from_zip(zf: zipfile.ZipFile) -> int | None:
    """
    Find XOR key from any per-file comment containing b'cmt-k:XX'.
    (Your code puts it on ops_memo.txt, but we search all to be resilient.)
    """
    for info in zf.infolist():
        c = info.comment or b""
        m = KEY_RE.search(c)
        if m:
            return int(m.group(1), 16)
    return None

def decrypt_comment(zcomment: bytes, key: int) -> bytes | None:
    """
    Parse archive comment and decrypt the ciphertext following HDR.
    """
    idx = zcomment.find(HDR)
    if idx == -1:
        return None
    cipher = zcomment[idx + len(HDR):]
    if not cipher:
        return None
    return xor_bytes(cipher, key)

def solve_from_outer_zip(path: str) -> str | None:
    with zipfile.ZipFile(path, "r") as outer:
        # only consider inner zips that match your naming scheme
        inner_names = [n for n in outer.namelist()
                       if re.fullmatch(r"dead_drop_\d{2}\.zip", n)]

        if not inner_names:
            raise RuntimeError("No inner dead_drop_XX.zip files found inside dead_drop.zip")

        for name in sorted(inner_names):
            inner_bytes = outer.read(name)

            # Open inner zip from bytes (no extraction)
            with zipfile.ZipFile(io.BytesIO(inner_bytes), "r") as inner:
                key = extract_key_from_zip(inner)
                if key is None:
                    continue

                plain = decrypt_comment(inner.comment or b"", key)
                if plain is None:
                    continue

                # Real payload format: b"T3:" + hex(token3)
                if plain.startswith(b"T3:"):
                    hexpart = plain[3:].strip()

                    # hexpart should be ASCII hex; if not, skip
                    try:
                        token_bytes = binascii.unhexlify(hexpart)
                        token = token_bytes.decode("utf-8", errors="strict")
                    except Exception:
                        continue

                    # Basic sanity check
                    if "PCCC{" in token and token.endswith("}"):
                        return f"{token} (from {name})"
                    return f"{token} (from {name})"

                # Decoys are OP:... ; ignore
        return None

def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} /path/to/dead_drop.zip", file=sys.stderr)
        sys.exit(2)

    path = sys.argv[1]
    try:
        result = solve_from_outer_zip(path)
    except Exception as e:
        print(f"[-] Error: {e}", file=sys.stderr)
        sys.exit(1)

    if not result:
        print("[-] Token 3 not found. Verify your dead_drop.zip contains the 10 inner zips and that inner zips have comments.")
        sys.exit(1)

    print(f"[+] TOKEN3: {result}")

if __name__ == "__main__":
    main()