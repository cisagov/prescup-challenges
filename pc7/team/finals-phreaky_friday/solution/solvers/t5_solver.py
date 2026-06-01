#!/usr/bin/env python3
import argparse, base64, hashlib, math, sys
import numpy as np
import soundfile as sf
from PIL import Image

MAGIC = b"T5HDRv1!"

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

def read_lsb_bits_from_wav(path: str) -> np.ndarray:
    audio, sr = sf.read(path, always_2d=False)
    if audio.ndim > 1:
        audio = audio[:,0]
    # We expect PCM_16 saved; if float, quantize consistently
    if np.issubdtype(audio.dtype, np.floating):
        ints = np.int16(np.round(np.clip(audio, -1, 1) * 32767.0))
    else:
        ints = audio.astype(np.int16, copy=False)
    bits = (ints & 1).astype(np.uint8)
    return bits

def find_magic(bits: np.ndarray, step=1, max_bits=None) -> int:
    if max_bits is None or max_bits > bits.size:
        max_bits = bits.size
    magic_bits = np.unpackbits(np.frombuffer(MAGIC, dtype=np.uint8), bitorder="big")
    m = magic_bits.size
    for pos in range(0, max_bits - m, step):
        seg = bits[pos:pos+m]
        if np.array_equal(seg, magic_bits):
            return pos
    return -1

def bits_to_bytes(be_bits: np.ndarray) -> bytes:
    nbytes = be_bits.size // 8
    return np.packbits(be_bits[:nbytes*8].reshape(-1,8), axis=1, bitorder="big").tobytes()

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--wav", required=True)
    ap.add_argument("--png", required=True)
    ap.add_argument("--atlas", required=True,
                    help="Exact atlas string printed on PNG (ORDER: ...)")
    ap.add_argument("--scan-max-bits", type=int, default=200000)
    ap.add_argument("--scan-step", type=int, default=1)
    ap.add_argument("-v", action="store_true")
    args = ap.parse_args()

    atlas = list(args.atlas.strip())
    A = len(atlas)
    bits_per = int(math.ceil(math.log2(A)))

    key16 = derive_key16_from_png(args.png)
    if args.v:
        print(f"[i] key16 from PNG: {key16.hex()} (atlas size={A}, bits/symbol={bits_per})")

    bits = read_lsb_bits_from_wav(args.wav)
    if args.v:
        print(f"[i] WAV loaded: {args.wav}  sr=44100  LSB-bits={bits.size}")

    # locate header
    pos = find_magic(bits, step=args.scan_step,
                     max_bits=min(args.scan_max_bits, bits.size))
    if pos < 0:
        print("[!] MAGIC header not found. Check difficulty or widen scan region.")
        sys.exit(1)

    # read header bytes: MAGIC(8) | n_symbols(2) | bits_per(1) | hop(1) | start_bit(4) | reserved(4)
    header_bits_len = (8 + 2 + 1 + 1 + 4 + 4) * 8
    hb = bits[pos : pos + header_bits_len]
    header = bits_to_bytes(hb)

    # parse
    if header[:8] != MAGIC:
        print("[!] MAGIC mismatch (race or wrong pos)")
        sys.exit(1)

    n_symbols = int.from_bytes(header[8:10], "big")
    hdr_bits_per = header[10]
    hop = header[11]
    start_bit = int.from_bytes(header[12:16], "big")
    if args.v:
        print(f"[i] header: n_symbols={n_symbols} bits_per={hdr_bits_per} hop={hop} start_bit={start_bit}")

    # payload bits begin right after header
    payload_start = pos + header_bits_len
    payload_bits = []
    p = payload_start
    for _ in range(n_symbols):
        sym_bits = []
        for b in range(hdr_bits_per - 1, -1, -1):  # big-endian per symbol
            p += hop
            if p >= bits.size:
                print("[!] Ran out of bits; WAV too short?")
                sys.exit(1)
            sym_bits.append(bits[p])
        payload_bits.extend(sym_bits)

    # pack symbols to integers
    payload_bits = np.array(payload_bits, dtype=np.uint8)
    # reshape to symbols (hdr_bits_per each)
    sym_vals = []
    for i in range(0, payload_bits.size, hdr_bits_per):
        v = 0
        for b in range(hdr_bits_per):
            v = (v << 1) | int(payload_bits[i+b])
        sym_vals.append(v)

    # unmask with keystream
    ks = stream_keystream(key16, n_symbols)
    unmasked = [ (sym_vals[i] - (ks[i] % A)) % A for i in range(n_symbols) ]

    # map indices -> chars
    def to_char(idx: int) -> str:
        if not (0 <= idx < A):
            return "?"
        return atlas[idx]

    text = "".join(to_char(i) for i in unmasked)
    if args.v:
        print(f"[i] decoded text (raw): {text}")

    # split at last '-' for TOKEN-CRC32B32
    if "-" not in text:
        print(f"[?] Decoded but no '-' found. Decoded text: {text}")
        sys.exit(2)

    token_core, crc_b32 = text.rsplit("-", 1)

    # base32 decode (pad to multiple of 8)
    pad_len = (-len(crc_b32)) % 8
    crc_bytes = None
    try:
        crc_bytes = base64.b32decode(crc_b32 + ("=" * pad_len), casefold=False)
    except Exception:
        print(f"[?] CRC portion not valid base32. Decoded text: {text}")
        sys.exit(3)

    if len(crc_bytes) != 2:
        print(f"[?] CRC base32 decoded to {len(crc_bytes)} bytes, expected 2. Text: {text}")
        sys.exit(3)

    crc_expected = int.from_bytes(crc_bytes, "big")
    # CRC is computed over the FULL token including PCCC{} wrapper
    full_token = f"PCCC{{{token_core}}}"
    crc_actual = crc16_ccitt_false(full_token.encode("ascii"))

    if crc_expected != crc_actual:
        print(f"[!] CRC mismatch. token='{full_token}' expected={crc_expected:04X} actual={crc_actual:04X}")
        sys.exit(4)
    print("\n=== TOKEN 5 ===")
    print(full_token)

if __name__ == "__main__":
    main()