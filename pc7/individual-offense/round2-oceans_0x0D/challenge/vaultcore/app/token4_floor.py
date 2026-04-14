from __future__ import annotations
import base64, hashlib, hmac, os, struct, time
import zlib
import secrets

def _build_floor_frame(floor_code: str) -> bytes:
    """
    Frame format:
    b"T4" | len(1 byte) | floor_code | crc32(4 bytes LE)
    """
    code_bytes = floor_code.encode("ascii")
    if not (8 <= len(code_bytes) <= 32):
        raise ValueError("invalid floor code length")

    header = b"T4" + bytes([len(code_bytes)])
    body = header + code_bytes
    crc = zlib.crc32(body) & 0xffffffff

    return body + struct.pack("<I", crc)

def _keystream(key: bytes, nonce: bytes, length: int, block: int = 32) -> bytes:
    out = bytearray()
    counter = 0
    while len(out) < length:
        ctr = struct.pack("<I", counter)
        digest = hmac.new(key, b"T4|STREAM|" + nonce + ctr, hashlib.sha256).digest()
        out.extend(digest[:block])
        counter += 1
    return bytes(out[:length])

def xor_encrypt(key: bytes, nonce: bytes, plaintext: bytes, block: int = 32) -> bytes:
    ks = _keystream(key, nonce, len(plaintext), block=block)
    return bytes([p ^ k for p, k in zip(plaintext, ks)])

def make_bmp_with_lsb_message(message: bytes, width: int = 512, height: int = 256, lsb_bits: int = 1) -> bytes:
    # 24-bit BMP, BGR pixels, padded rows to 4 bytes.
    if lsb_bits not in (1, 2):
        raise ValueError("lsb_bits must be 1 or 2")
    header_size = 54
    row_bytes = width * 3
    pad = (4 - (row_bytes % 4)) % 4
    stride = row_bytes + pad
    pixel_bytes_len = stride * height

    # Fill pixels with pseudo-random but deterministic-ish noise (time-based).
    seed = hashlib.sha256(b"T4|PIX|" + struct.pack("<I", int(time.time()))).digest()
    pixels = bytearray(os.urandom(pixel_bytes_len))
    for i in range(0, len(pixels), 32):
        block = hashlib.sha256(seed + struct.pack("<I", i)).digest()
        pixels[i:i+32] = block[:min(32, len(pixels)-i)]

    # LSB embed: [len(2 bytes LE)] + message
    if len(message) > 4096:
        raise ValueError("message too long")
    payload = struct.pack("<H", len(message)) + message
    bits = []
    for b in payload:
        for j in range(8):
            bits.append((b >> (7-j)) & 1)

    if lsb_bits == 2:
        # pack bits into 2-bit symbols
        symbols = []
        for i in range(0, len(bits), 2):
            a = bits[i]
            b = bits[i+1] if i+1 < len(bits) else 0
            symbols.append((a<<1) | b)
    else:
        symbols = bits

    capacity = len(pixels)
    if len(symbols) > capacity:
        raise ValueError("image too small for payload")

    if lsb_bits == 1:
        for i, bit in enumerate(symbols):
            pixels[i] = (pixels[i] & 0xFE) | bit
    else:
        for i, sym in enumerate(symbols):
            pixels[i] = (pixels[i] & 0xFC) | (sym & 0x3)

    # BMP headers
    file_size = header_size + len(pixels)
    bfType = b"BM"
    bfOffBits = header_size
    bmp_file_header = struct.pack("<2sIHHI", bfType, file_size, 0, 0, bfOffBits)
    biSize = 40
    biPlanes = 1
    biBitCount = 24
    biCompression = 0
    biSizeImage = len(pixels)
    biXPelsPerMeter = 2835
    biYPelsPerMeter = 2835
    biClrUsed = 0
    biClrImportant = 0
    bmp_info_header = struct.pack(
        "<IIIHHIIIIII",
        biSize, width, height, biPlanes, biBitCount, biCompression, biSizeImage,
        biXPelsPerMeter, biYPelsPerMeter, biClrUsed, biClrImportant
    )
    return bmp_file_header + bmp_info_header + bytes(pixels)

def stego_export_blob(
    *,
    ghost_secret: bytes,
    floor_code: str,
    lsb_bits: int,
    cipher_block: int,
):
    # --------------------------------------------------
    # 1. Build framed plaintext (STABLE)
    # --------------------------------------------------
    frame = _build_floor_frame(floor_code)

    # --------------------------------------------------
    # 2. Create carrier buffer
    # --------------------------------------------------
    # Carrier must be large enough for LSB embedding
    carrier_len = len(frame) * (8 // lsb_bits) + 16
    carrier = bytearray(secrets.token_bytes(carrier_len))

    # --------------------------------------------------
    # 3. Embed frame using LSB stego (BEFORE encryption)
    # --------------------------------------------------
    bitmask = (1 << lsb_bits) - 1
    bitstream = []

    for b in frame:
        for i in reversed(range(0, 8, lsb_bits)):
            bitstream.append((b >> i) & bitmask)

    for i, bits in enumerate(bitstream):
        carrier[i] = (carrier[i] & ~bitmask) | bits

    # --------------------------------------------------
    # 4. Encrypt entire carrier (AFTER stego)
    # --------------------------------------------------
    nonce = secrets.token_bytes(16)

    keystream = b""
    ctr = 0
    while len(keystream) < len(carrier):
        h = hashlib.sha256(
            ghost_secret + nonce + ctr.to_bytes(4, "little")
        ).digest()
        keystream += h[:cipher_block]
        ctr += 1

    cipher = bytes(a ^ b for a, b in zip(carrier, keystream))

    # --------------------------------------------------
    # 5. Return export blob
    # --------------------------------------------------
    return {
        "format": "T4-STEG-V2",
        "nonce_b64": base64.b64encode(nonce).decode(),
        "cipher_b64": base64.b64encode(cipher).decode(),
        "bytes": len(cipher),
        "hint": "LSB->decrypt->frame",
    }
