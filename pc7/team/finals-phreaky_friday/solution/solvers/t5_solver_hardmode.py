#!/usr/bin/env python3
import argparse
import base64
import hashlib
import math
import sys
from typing import List, Tuple, Optional

import numpy as np
import soundfile as sf

MAGIC = b"T5HDRv1!"
DEFAULT_ATLAS_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-{}"

def crc16_ccitt_false(data: bytes) -> int:
    crc = 0xFFFF
    for b in data:
        crc ^= b << 8
        for _ in range(8):
            if crc & 0x8000:
                crc = ((crc << 1) ^ 0x1021) & 0xFFFF
            else:
                crc = (crc << 1) & 0xFFFF
    return crc

def derive_key16_from_png(png_path: str) -> bytes:
    with open(png_path, "rb") as f:
        png_bytes = f.read()
    return hashlib.sha256(png_bytes + b"::PHR_T5_KEY").digest()[:16]

def stream_keystream(key16: bytes, n: int) -> bytes:
    out = bytearray()
    ctr = 0
    while len(out) < n:
        out.extend(hashlib.sha256(key16 + ctr.to_bytes(8, "big")).digest())
        ctr += 1
    return bytes(out[:n])

def read_lsb_bits_from_wav(path: str) -> Tuple[np.ndarray, int]:
    audio, sr = sf.read(path, always_2d=False)
    if audio.ndim > 1:
        audio = audio[:, 0]
    if np.issubdtype(audio.dtype, np.floating):
        ints = np.int16(np.round(np.clip(audio, -1, 1) * 32767.0))
    else:
        ints = audio.astype(np.int16, copy=False)
    bits = (ints & 1).astype(np.uint8)
    return bits, sr

def find_magic(bits: np.ndarray, step: int = 1, max_bits: Optional[int] = None) -> int:
    if max_bits is None or max_bits > bits.size:
        max_bits = bits.size
    magic_bits = np.unpackbits(np.frombuffer(MAGIC, dtype=np.uint8), bitorder="big")
    m = magic_bits.size
    for pos in range(0, max_bits - m + 1, step):
        if np.array_equal(bits[pos:pos + m], magic_bits):
            return pos
    return -1

def bits_to_bytes(be_bits: np.ndarray) -> bytes:
    nbytes = be_bits.size // 8
    if nbytes <= 0:
        return b""
    arr = be_bits[:nbytes * 8].reshape(-1, 8)
    return np.packbits(arr, axis=1, bitorder="big").tobytes()

def decode_masked_indices(masked: List[int], atlas: List[str], key16: bytes) -> str:
    ks = stream_keystream(key16, len(masked))
    decoded = []
    A = len(atlas)
    for i, mv in enumerate(masked):
        idx = (mv - (ks[i] % A)) % A
        decoded.append(atlas[idx])
    return "".join(decoded)

def validate_payload_text(payload_text: str) -> Tuple[bool, str]:
    try:
        token_core, crc_b32 = payload_text.rsplit("-", 1)
    except ValueError:
        return False, "payload missing trailing CRC separator"
    if len(crc_b32) != 4:
        return False, f"CRC suffix length {len(crc_b32)} != 4"
    try:
        crc_expected = int.from_bytes(base64.b32decode(crc_b32 + "===="), "big")
    except Exception as e:
        return False, f"invalid CRC base32: {e}"
    full_token = f"PCCC{{{token_core}}}"
    crc_actual = crc16_ccitt_false(full_token.encode("ascii"))
    if crc_expected != crc_actual:
        return False, (
            f"CRC mismatch for {full_token}: expected={crc_expected:04X} actual={crc_actual:04X}"
        )
    return True, full_token

def decode_header_mode(bits: np.ndarray, atlas: List[str], key16: bytes,
                       scan_max_bits: int, scan_step: int, verbose: bool = False) -> Optional[str]:
    pos = find_magic(bits, step=scan_step, max_bits=min(scan_max_bits, bits.size))
    if pos < 0:
        return None

    header_bits_len = (8 + 2 + 1 + 1 + 4 + 4) * 8
    header = bits_to_bytes(bits[pos:pos + header_bits_len])
    if header[:8] != MAGIC:
        return None

    n_symbols = int.from_bytes(header[8:10], "big")
    hdr_bits_per = header[10]
    hop = header[11]
    start_bit = int.from_bytes(header[12:16], "big")

    if verbose:
        print(f"[header] found @ bit {pos}")
        print(f"[header] n_symbols={n_symbols} bits_per={hdr_bits_per} hop={hop} start_bit={start_bit}")

    payload_start = pos + header_bits_len
    masked = []
    p = payload_start
    for _ in range(n_symbols):
        val = 0
        for _bit in range(hdr_bits_per):
            p += hop
            if p >= bits.size:
                return None
            val = (val << 1) | int(bits[p])
        masked.append(val)

    payload_text = decode_masked_indices(masked, atlas, key16)
    ok, result = validate_payload_text(payload_text)
    if verbose:
        print(f"[header] decoded payload={payload_text}")
        print(f"[header] validation={result}")
    return result if ok else None

def expected_symbol_count_from_token_shape(prefix: str, body_len: int, crc_chars: int = 4) -> int:
    # payload_text = "<prefix>-<body>" + "-" + "<crc>"
    return len(prefix) + 1 + body_len + 1 + crc_chars

def decode_hard_mode(bits: np.ndarray, atlas: List[str], key16: bytes,
                     prefix: str = "PHR", body_len: int = 6, verbose: bool = False) -> Optional[str]:
    A = len(atlas)
    bits_per = int(math.ceil(math.log2(A)))
    n_symbols = expected_symbol_count_from_token_shape(prefix, body_len)

    rng = np.random.default_rng(int.from_bytes(key16, "big"))
    start_bit = int(rng.integers(2048, 20000))
    if verbose:
        print(f"[hard] bits_per={bits_per} n_symbols={n_symbols} start_bit={start_bit}")

    pos = start_bit
    masked = []
    for si in range(n_symbols):
        bitorder_little = (rng.integers(0, 2) == 1)
        bit_range = range(bits_per) if bitorder_little else range(bits_per - 1, -1, -1)
        val = 0
        if bitorder_little:
            for b in bit_range:
                hop = int(2 + rng.integers(0, 6))
                pos += hop
                if pos >= bits.size:
                    return None
                bit = int(bits[pos])
                val |= (bit << b)
        else:
            for b in bit_range:
                hop = int(2 + rng.integers(0, 6))
                pos += hop
                if pos >= bits.size:
                    return None
                bit = int(bits[pos])
                val |= (bit << b)
        masked.append(val)
        if verbose:
            bo = "little" if bitorder_little else "big"
            print(f"[hard] symbol[{si:02d}] masked={val:02d} bitorder={bo}")

    payload_text = decode_masked_indices(masked, atlas, key16)
    ok, result = validate_payload_text(payload_text)
    if verbose:
        print(f"[hard] decoded payload={payload_text}")
        print(f"[hard] validation={result}")
    return result if ok else None

def main():
    ap = argparse.ArgumentParser(
        description="Quartz Token 5 solver for EASY/MEDIUM header modes and HARD keyed mode."
    )
    ap.add_argument("--wav", required=True)
    ap.add_argument("--png", required=True)
    ap.add_argument("--atlas", required=True, help="Atlas order exactly as printed on the glyph PNG.")
    ap.add_argument("--mode", choices=["auto", "header", "hard"], default="auto")
    ap.add_argument("--scan-max-bits", type=int, default=200000)
    ap.add_argument("--scan-step", type=int, default=1)
    ap.add_argument("--prefix", default="PHR")
    ap.add_argument("--body-len", type=int, default=6,
                    help="Length of random suffix after '<prefix>-'. Default matches PHR-XXXXXX.")
    ap.add_argument("--raw-inner", action="store_true")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args()

    atlas = list(args.atlas.strip())
    if set(DEFAULT_ATLAS_ALPHABET) - set(atlas):
        print("[!] Warning: atlas does not appear to contain the expected base alphabet.", file=sys.stderr)

    key16 = derive_key16_from_png(args.png)
    bits, sr = read_lsb_bits_from_wav(args.wav)

    if args.verbose:
        print(f"[i] WAV={args.wav} sr={sr} bits={bits.size}")
        print(f"[i] PNG={args.png}")
        print(f"[i] key16={key16.hex()}")
        print(f"[i] atlas-size={len(atlas)} bits/symbol={int(math.ceil(math.log2(len(atlas))))}")

    full_token = None
    tried = []

    if args.mode in ("auto", "header"):
        tried.append("header")
        full_token = decode_header_mode(
            bits, atlas, key16, args.scan_max_bits, args.scan_step, verbose=args.verbose
        )
        if full_token and args.verbose:
            print("[+] header mode succeeded")

    if full_token is None and args.mode in ("auto", "hard"):
        tried.append("hard")
        full_token = decode_hard_mode(
            bits, atlas, key16, prefix=args.prefix, body_len=args.body_len, verbose=args.verbose
        )
        if full_token and args.verbose:
            print("[+] hard mode succeeded")

    if full_token is None:
        print(f"[!] Unable to recover Token 5. Modes tried: {', '.join(tried)}")
        sys.exit(2)

    if args.raw_inner:
        print(full_token[5:-1])
    else:
        print("\n=== TOKEN 5 ===")
        print(full_token)

if __name__ == "__main__":
    main()