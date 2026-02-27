#!/usr/bin/env python3
"""
Token 4 solver - Ocean's 0x0D (False Floor)

Flow:
  - GET  /api/ops/surveillance/export  -> {nonce_b64, cipher_b64, ...}
  - Decrypt cipher using ghost_secret (from Token 3)
  - Extract framed plaintext from LSB stego carrier
  - POST /api/ops/floor/enter {code:<floor_code>}
  - GET  /api/ops/maintenance/floor-slip -> token4 in "auth"

Usage examples:
  python3 solve_token4.py --base http://vaultcore.pccc:8080 --ghost-hex 0123...
  python3 solve_token4.py --base http://vaultcore.pccc:8080 --ghost-b64 SGVsbG8...

Notes:
  - If SOC blocks you (403/423), you need to reduce alert/lockdown before retrying.
  - Script auto-tries lsb_bits = 1 then 2 (server default is usually 1).
"""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import struct
import sys
import zlib
from typing import Optional, Tuple

import requests


def b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"), validate=True)


def build_keystream(ghost_secret: bytes, nonce: bytes, length: int, cipher_block: int = 32) -> bytes:
    out = bytearray()
    ctr = 0
    while len(out) < length:
        h = hashlib.sha256(ghost_secret + nonce + ctr.to_bytes(4, "little")).digest()
        out.extend(h[:cipher_block])
        ctr += 1
    return bytes(out[:length])


def decrypt_export(ghost_secret: bytes, nonce: bytes, cipher: bytes, cipher_block: int = 32) -> bytes:
    ks = build_keystream(ghost_secret, nonce, len(cipher), cipher_block=cipher_block)
    return bytes(a ^ b for a, b in zip(cipher, ks))


def extract_frame_from_lsb(carrier: bytes, lsb_bits: int) -> Tuple[bytes, str]:
    """
    Carrier contains embedded symbols in its lowest lsb_bits.
    Frame format (from server code):
      b"T4" | len(1 byte) | floor_code (ascii) | crc32(4 bytes LE)
    """
    if lsb_bits not in (1, 2):
        raise ValueError("lsb_bits must be 1 or 2")

    mask = (1 << lsb_bits) - 1
    symbols = [b & mask for b in carrier]

    # Helpers to reconstruct one byte from N symbols
    if lsb_bits == 1:
        shifts = list(range(7, -1, -1))  # 7..0
        per_byte = 8
    else:
        shifts = [6, 4, 2, 0]
        per_byte = 4

    def read_byte(byte_index: int) -> int:
        start = byte_index * per_byte
        chunk = symbols[start : start + per_byte]
        if len(chunk) != per_byte:
            raise ValueError("carrier too short while reading")
        val = 0
        for sym, sh in zip(chunk, shifts):
            val |= (sym & mask) << sh
        return val

    # Read header + length first (3 bytes)
    h0 = read_byte(0)
    h1 = read_byte(1)
    ln = read_byte(2)

    if bytes([h0, h1]) != b"T4":
        raise ValueError("bad frame magic (expected T4)")

    if not (8 <= ln <= 32):
        raise ValueError(f"invalid floor code length: {ln}")

    # Total frame bytes = 2 + 1 + ln + 4
    total = 2 + 1 + ln + 4
    frame = bytes(read_byte(i) for i in range(total))

    # Validate CRC32
    body = frame[:-4]
    crc_expected = struct.unpack("<I", frame[-4:])[0]
    crc_actual = zlib.crc32(body) & 0xFFFFFFFF
    if crc_actual != crc_expected:
        raise ValueError("crc mismatch (wrong lsb_bits or wrong secret)")

    floor_code = frame[3 : 3 + ln].decode("ascii", errors="strict")
    return frame, floor_code


def http_json(method: str, url: str, **kwargs) -> dict:
    r = requests.request(method, url, timeout=10, **kwargs)
    # give nice error context
    if not (200 <= r.status_code < 300):
        try:
            detail = r.json()
        except Exception:
            detail = r.text
        raise RuntimeError(f"{method} {url} -> {r.status_code}: {detail}")
    return r.json()


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--base",default="http://vaultcore.pccc:8080", help="Base URL for vaultcore, e.g. http://vaultcore.pccc:8080")
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--ghost-hex", help="Ghost secret (bytes) as hex string (no 0x prefix)")
    g.add_argument("--ghost-b64", help="Ghost secret (bytes) as base64 string")
    ap.add_argument("--cipher-block", type=int, default=32, help="Cipher block size (default: 32)")
    ap.add_argument("--lsb-bits", type=int, choices=[1, 2], default=None, help="Force LSB bits (otherwise auto-try 1 then 2)")
    args = ap.parse_args()

    base = args.base.rstrip("/")

    if args.ghost_hex:
        try:
            ghost_secret = binascii.unhexlify(args.ghost_hex.strip())
        except binascii.Error as e:
            print(f"[!] Bad --ghost-hex: {e}", file=sys.stderr)
            return 2
    else:
        try:
            ghost_secret = b64d(args.ghost_b64.strip())
        except Exception as e:
            print(f"[!] Bad --ghost-b64: {e}", file=sys.stderr)
            return 2

    print("[*] Fetching surveillance export blob...")
    blob = http_json("GET", f"{base}/api/ops/surveillance/export")

    nonce = b64d(blob["nonce_b64"])
    cipher = b64d(blob["cipher_b64"])
    cipher_block = int(args.cipher_block)

    print(f"[*] Export bytes: {len(cipher)}  format: {blob.get('format')}  hint: {blob.get('hint')}")
    print("[*] Decrypting export...")
    carrier = decrypt_export(ghost_secret, nonce, cipher, cipher_block=cipher_block)

    # Extract frame/code (auto-try lsb_bits)
    lsb_try = [args.lsb_bits] if args.lsb_bits else [1, 2]
    last_err: Optional[Exception] = None
    frame = None
    floor_code = None

    for lsb_bits in lsb_try:
        try:
            frame, floor_code = extract_frame_from_lsb(carrier, lsb_bits=lsb_bits)
            print(f"[*] Extracted frame via LSB={lsb_bits}, floor_code={floor_code}")
            break
        except Exception as e:
            last_err = e

    if floor_code is None:
        print(f"[!] Failed to extract frame/code. Last error: {last_err}", file=sys.stderr)
        return 3

    print("[*] Submitting floor code...")
    _ = http_json("POST", f"{base}/api/ops/floor/enter", json={"code": floor_code})

    print("[*] Pulling slip for Token 4...")
    slip = http_json("GET", f"{base}/api/ops/maintenance/floor-slip")

    token4 = slip.get("auth")
    if not token4:
        print(f"[!] No 'auth' field in slip response: {json.dumps(slip, indent=2)}", file=sys.stderr)
        return 4

    print("\n✅ TOKEN 4:", token4)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())