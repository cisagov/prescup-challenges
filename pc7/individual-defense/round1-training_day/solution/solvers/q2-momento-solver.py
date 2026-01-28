#!/usr/bin/env python3
import base64
import binascii
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Tuple


MARKER = b"LCM2"
VERSION_EXPECTED = 2

# Reasonable safety limits
MAX_LEN = 4096          # payload bytes
MAX_SCAN_HITS = 1000    # avoid pathological cases


@dataclass
class Hit:
    offset: int
    version: int
    key: int
    length: int
    xordata: bytes

    def decode_with_key(self, key: int) -> Tuple[Optional[str], Optional[bytes]]:
        decoded = bytes(b ^ key for b in self.xordata)
        try:
            # Base64 strings should be ASCII; strip whitespace just in case.
            b64_str = decoded.decode("ascii", errors="strict").strip()
        except UnicodeDecodeError:
            return None, None

        # Strict base64 validation to reduce false positives
        try:
            raw = base64.b64decode(b64_str, validate=True)
        except Exception:
            return b64_str, None

        return b64_str, raw


def find_all(data: bytes, needle: bytes) -> List[int]:
    offsets = []
    start = 0
    while True:
        idx = data.find(needle, start)
        if idx == -1:
            break
        offsets.append(idx)
        start = idx + 1
        if len(offsets) >= MAX_SCAN_HITS:
            break
    return offsets


def parse_hit(data: bytes, off: int) -> Optional[Hit]:
    """
    Format:
      MARKER(4) | VER(1) | KEY(1) | LEN(2 LE) | XOR_DATA(LEN)
    """
    hdr_len = 4 + 1 + 1 + 2
    if off + hdr_len > len(data):
        return None

    if data[off:off+4] != MARKER:
        return None

    ver = data[off+4]
    key = data[off+5]
    length = int.from_bytes(data[off+6:off+8], "little")

    if length <= 0 or length > MAX_LEN:
        return None
    if off + hdr_len + length > len(data):
        return None

    xordata = data[off+8:off+8+length]
    return Hit(offset=off, version=ver, key=key, length=length, xordata=xordata)


def looks_like_token(raw: bytes) -> bool:
    # We expect something like b"TOKEN2: ..."
    return raw.startswith(b"TOKEN2: ")


def main() -> int:
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} /path/to/memory_dump.raw", file=sys.stderr)
        return 2

    path = Path(sys.argv[1])
    data = path.read_bytes()

    offsets = find_all(data, MARKER)
    if not offsets:
        print("[-] Marker LCM2 not found.")
        return 1

    hits: List[Hit] = []
    for off in offsets:
        hit = parse_hit(data, off)
        if hit:
            hits.append(hit)

    if not hits:
        print("[-] Marker found but no valid blobs parsed (length/version bounds).")
        return 1

    found_any = False

    for hit in hits:
        print(f"[+] Found blob at offset {hit.offset} (ver={hit.version}, key=0x{hit.key:02X}, len={hit.length})")

        # If version is unexpected, still try (could be decoy)
        if hit.version != VERSION_EXPECTED:
            print(f"    [!] Unexpected version {hit.version} (expected {VERSION_EXPECTED}); will still attempt decode.")

        # First try using embedded key if in range
        decoded_b64, raw = hit.decode_with_key(hit.key)
        if raw and looks_like_token(raw):
            print(f"    [✓] Base64: {decoded_b64}")
            print(f"    [🎯] {raw.decode('utf-8', errors='replace')}")
            found_any = True
            continue

        # If embedded key failed or produced non-token, brute force 0xA1..0xFF
        print("    [*] Embedded key did not yield TOKEN2; brute-forcing keys 0xA1..0xFF...")
        for key in range(0xA1, 0x100):
            decoded_b64, raw = hit.decode_with_key(key)
            if raw and looks_like_token(raw):
                print(f"    [✓] Key: 0x{key:02X}")
                print(f"    [✓] Base64: {decoded_b64}")
                print(f"    [🎯] {raw.decode('utf-8', errors='replace')}")
                found_any = True
                break
        else:
            # Give a tiny hint for debugging
            if decoded_b64:
                preview = decoded_b64[:80].replace("\n", "")
                print(f"    [-] No TOKEN2 found. Last b64-ish preview: {preview!r}")
            else:
                print("    [-] No TOKEN2 found; data not decodable as ASCII base64 under tested keys.")

    if not found_any:
        print("[-] No valid TOKEN2 recovered from any blob.")
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
