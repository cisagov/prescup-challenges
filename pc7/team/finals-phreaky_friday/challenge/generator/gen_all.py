#!/usr/bin/env python3
import os, io, math, zipfile, tarfile, argparse, struct, socket, base64, hashlib, numpy as np, soundfile as sf
from PIL import Image, ImageDraw, ImageFont
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from gen_audio_utils import * # sine_wave, save_wav, make_spectrogram_glyphs
from gen_pcap_utils import * #write_udp_pcap 

# ----- WAV helpers -----
def sine_wave(freq, length_s, sr=44100, amplitude=0.22):
    t = np.linspace(0, length_s, int(sr*length_s), endpoint=False, dtype=np.float32)
    return (amplitude * np.sin(2*np.pi*freq*t)).astype(np.float32)

def save_wav(path, samples, sr=44100, normalize=False):
    x = np.asarray(samples, dtype=np.float32)
    if normalize:
        m = np.max(np.abs(x)) if x.size else 0.0
        if m > 0: x = (x / m * 0.9).astype(np.float32)
    sf.write(path, x, sr, subtype="PCM_16")

def embed_lsb_wav(samples, payload_bytes):
    """Embed bytes into the LSB of int16 samples (big-endian per byte). No renormalize."""
    s = np.asarray(samples, dtype=np.float32)
    s16 = np.round(np.clip(s, -1, 1) * 32767.0).astype(np.int16)
    bits = np.unpackbits(np.frombuffer(payload_bytes, dtype=np.uint8), bitorder="big")
    if bits.size > s16.size:
        raise ValueError("Not enough samples for LSB payload")
    mod = s16.copy()
    mod[:bits.size] = (mod[:bits.size] & ~1) | bits
    return (mod.astype(np.float32) / 32767.0)

# ----- Tiny PCAP writer (Ethernet+IPv4+UDP) -----
def _ip_checksum(hdr):
    s = 0
    for i in range(0, len(hdr), 2):
        w = (hdr[i] << 8) + (hdr[i+1] if i+1 < len(hdr) else 0)
        s = (s + w) & 0xffffffff
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff

def write_udp_pcap(path, src_ip, dst_ip, src_port, dst_port, payloads, start_ts=1_700_000_000.0, delta=0.01):
    with open(path, "wb") as f:
        # PCAP global header
        f.write(struct.pack("<IHHIIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        ts = start_ts
        mac_src = b"\xaa\xaa\xaa\xaa\xaa\xaa"
        mac_dst = b"\xbb\xbb\xbb\xbb\xbb\xbb"
        eth_type = b"\x08\x00"
        s_ip = socket.inet_aton(src_ip)
        d_ip = socket.inet_aton(dst_ip)
        for p in payloads:
            udp_len = 8 + len(p)
            udp_hdr = struct.pack("!HHHH", src_port, dst_port, udp_len, 0)
            ver_ihl, tos = 0x45, 0
            tot_len, ident, flags_frag = 20 + udp_len, 0, 0x4000
            ttl, proto = 64, 17
            ip_wo = struct.pack("!BBHHHBBH4s4s", ver_ihl, tos, tot_len, ident, flags_frag, ttl, proto, 0, s_ip, d_ip)
            csum = _ip_checksum(ip_wo)
            ip_hdr = struct.pack("!BBHHHBBH4s4s", ver_ihl, tos, tot_len, ident, flags_frag, ttl, proto, csum, s_ip, d_ip)
            frame = mac_dst + mac_src + eth_type + ip_hdr + udp_hdr + p
            sec = int(ts); usec = int((ts-sec)*1_000_000)
            f.write(struct.pack("<IIII", sec, usec, len(frame), len(frame)))
            f.write(frame); ts += delta

# ----- T4 glyph atlas + keystream + CRC -----
def make_glyph_atlas(order, width=700, height=220, font_size=36, header="GLYPH ATLAS (ORDERED)"):
    cols = 12
    cell_w, cell_h = width // cols, (height-40)//4
    img = Image.new("L", (width, height), color=0)
    dr = ImageDraw.Draw(img)
    try:
        fnt = ImageFont.truetype("DejaVuSansMono.ttf", font_size)
        small = ImageFont.truetype("DejaVuSansMono.ttf", 16)
    except:
        fnt = ImageFont.load_default(); small = ImageFont.load_default()
    dr.text((10, 5), header, fill=255, font=small)
    for i, ch in enumerate(order):
        r, c = divmod(i, cols)
        x, y = c*cell_w, 40 + r*cell_h
        dr.rectangle([x, y, x+cell_w-1, y+cell_h-1], outline=120)
        dr.text((x+8, y+6), f"{i:02d}", fill=170, font=small)
        # center big glyph
        tw, th = dr.textbbox((0,0), ch, font=fnt)[2:]
        gx = x + (cell_w - tw)//2
        gy = y + (cell_h - th)//2 + 6
        dr.text((gx, gy), ch, fill=255, font=fnt)
    return img

def crc16_ccitt_false(data: bytes) -> int:
    crc = 0xFFFF
    for b in data:
        crc ^= b << 8
        for _ in range(8):
            if crc & 0x8000: crc = ((crc << 1) ^ 0x1021) & 0xFFFF
            else:            crc = (crc << 1) & 0xFFFF
    return crc

def stream_keystream(key16: bytes, n: int) -> bytes:
    """Deterministic keystream: concat SHA256(key || counter) blocks."""
    out = bytearray()
    ctr = 0
    while len(out) < n:
        out.extend(hashlib.sha256(key16 + ctr.to_bytes(8, "big")).digest())
        ctr += 1
    return bytes(out[:n])

def embed_lsb_wav_keyed(samples, indices, alphabet_size, key16):
    """
    Keyed LSB with hops and per-symbol bitorder.
    - hops in [2..7] chosen by RNG seeded from key
    - bitorder: rng bit -> 0: big, 1: little
    """
    rng = np.random.default_rng(int.from_bytes(key16, "big"))
    s = np.asarray(samples, dtype=np.float32)
    s16 = np.round(np.clip(s, -1, 1) * 32767.0).astype(np.int16)

    bits_per = math.ceil(math.log2(alphabet_size))
    # build bitstream for all indices with per-symbol bitorder
    stream = []
    for idx in indices:
        # choose bitorder for this symbol
        bitorder_little = (rng.integers(0, 2) == 1)
        if bitorder_little:
            for b in range(bits_per):
                stream.append((idx >> b) & 1)
        else:
            for b in range(bits_per-1, -1, -1):
                stream.append((idx >> b) & 1)

    # hop sequence
    hops = 2 + rng.integers(0, 6, size=len(stream))
    pos = 0
    mod = s16.copy()
    for bit, hop in zip(stream, hops):
        pos += int(hop)
        if pos >= mod.size: break
        mod[pos] = (mod[pos] & ~1) | int(bit)

    return (mod.astype(np.float32) / 32767.0)

def tokens_from_env():
    required = ["TOKEN_T1", "TOKEN_T2", "TOKEN_T3", "TOKEN_T4", "TOKEN_T5"]
    missing = [k for k in required if not os.environ.get(k)]
    if missing:
        raise SystemExit(f"[!] Missing token env vars: {', '.join(missing)}")
    return {
        "T1": os.environ["TOKEN_T1"],
        "T2": os.environ["TOKEN_T2"],
        "T3": os.environ["TOKEN_T3"],
        "T4": os.environ["TOKEN_T4"],
        "T5": os.environ["TOKEN_T5"],
    }

def build_t1(out_dir, token):
    """
    Wireshark-first T1:
      - Create WAV with LSB-embedded token (ASCII + NUL) into int16.
      - Packetize the WAV bytes into WHPR UDP frames.
      - Wireshark: Follow UDP Stream -> Save As (Raw) -> WAV is exact.
    """
    # 1) make audio with token in LSB (NO normalize after embedding)
    base = sine_wave(220, 5.0, amplitude=0.25)
    msg = token.encode("ascii") + b"\x00"
    ints = (np.clip(base, -1.0, 1.0) * 32767.0).round().astype(np.int16)
    bits = np.unpackbits(np.frombuffer(msg, dtype=np.uint8), bitorder="big")
    if bits.size > ints.size:
        raise ValueError("[T1] Carrier too short for token LSB payload")
    mod = ints.copy()
    mod[:len(bits)] = (mod[:len(bits)] & ~1) | bits

    wav_path = os.path.join(out_dir, "t1_calldata.wav")
    # write as PCM_16 without any renormalization
    sf.write(wav_path, mod.astype(np.int16), 44100, subtype="PCM_16")

    # 1b) SELF-CHECK: re-read and confirm the embedded bytes equal TOKEN_T1
    r, sr = sf.read(wav_path, always_2d=False)
    if r.ndim > 1: r = r[:,0]
    r_int16 = np.int16(np.round(np.clip(r, -1, 1) * 32767.0))
    r_bits = (r_int16 & 1).astype(np.uint8)[:len(bits)]
    r_bytes = np.packbits(r_bits, bitorder="big").tobytes().split(b"\x00",1)[0]
    assert r_bytes.decode("ascii") == token, \
        f"[T1] LSB verification failed. got={r_bytes!r} expected={token!r}"

    # 2) frame the WAV bytes into WHPR packets (magic|seq|len|chunk)
    wav_bytes = open(wav_path, "rb").read()
    CHUNK = 600
    pkts = []
    for seq, off in enumerate(range(0, len(wav_bytes), CHUNK)):
        chunk = wav_bytes[off:off+CHUNK]
        hdr = b"WHPR" + seq.to_bytes(2,"big") + len(chunk).to_bytes(2,"big")
        pkts.append(hdr + chunk)

    # 3) write PCAP
    pcap_path = os.path.join(out_dir, "t1_whisper_trace.pcap")
    write_udp_pcap(
        pcap_path,
        src_ip="10.10.10.1", dst_ip="10.10.10.2",
        src_port=40000, dst_port=40001,
        payloads=pkts, start_ts=1_700_000_000.0, delta=0.01
    )

    # Removes t1_calldata.wav after pcap is embedded
    os.remove(wav_path)

    # perms (optional)
    for fp in (wav_path, pcap_path):
        try: os.chmod(fp, 0o644)
        except: pass

    print(f"[T1] Embedded token from env OK: {token}")

def build_t2(out_dir, token):
    import secrets
    mask = 0x5A
    s = token.encode('ascii')
    half = len(s)//2
    part1 = bytes([b ^ mask for b in s[:half]])
    part2 = bytes([b ^ mask for b in s[half:]])
    with open(os.path.join(out_dir, 't2_clamstream.bin'),'wb') as f:
        f.write(b'CL'+bytes([mask,len(part1)])+part1)
        f.write(b'CL'+bytes([mask,len(part2)])+part2)
        for _ in range(40):
            f.write(b'CL'+bytes([0,4])+secrets.token_bytes(4))

def build_t3(out_dir, token_ascii: str):
    """
    T3: Reliable BFSK beacon carrying the ASCII token with CRC16-CCITT.
    Output: t3_snippet.wav

    Frame:
      PREAMBLE:  32 bits of 0x55 (01010101...) -> helps timing/AGC
      SYNC:      0xDDAA (16 bits, big-endian)
      LEN:       1 byte payload length (ASCII token)
      PAYLOAD:   token bytes (ASCII)
      CRC16:     CCITT-FALSE over LEN||PAYLOAD (big-endian 2 bytes)

    Modulation:
      BFSK @ 25 bps (bit_dur = 0.04s)
      bit 0 -> f0 = 1500 Hz
      bit 1 -> f1 = 2300 Hz
      SR = 44100 Hz
    """
    import numpy as np, os
    from Crypto.Hash import SHA256

    os.makedirs(out_dir, exist_ok=True)

    # ---- Parameters ----
    SR       = 44100
    F0       = 1500.0
    F1       = 2300.0
    BIT_DUR  = 0.04          # 25 bps
    AMP      = 0.30          # comfortable headroom
    PRE_BITS = 32            # preamble length in bits

    def crc16_ccitt_false(data: bytes) -> int:
        crc = 0xFFFF
        for b in data:
            crc ^= (b << 8) & 0xFFFF
            for _ in range(8):
                if crc & 0x8000:
                    crc = ((crc << 1) ^ 0x1021) & 0xFFFF
                else:
                    crc = (crc << 1) & 0xFFFF
        return crc

    # ---- Build frame ----
    payload = token_ascii.encode("ascii")
    if len(payload) > 255:
        raise ValueError("Token too long for this simple frame (max 255 bytes).")
    length = bytes([len(payload)])
    crc = crc16_ccitt_false(length + payload).to_bytes(2, "big")
    # Preamble: 0x55 0x55 ... -> (01010101...)
    pre_bits = []
    for _ in range(PRE_BITS // 8):
        pre_bits.extend([(0x55 >> (7 - i)) & 1 for i in range(8)])
    # Sync 0xDDAA (big-endian)
    sync_bits = [ (0xDD >> (7 - i)) & 1 for i in range(8) ] + \
                [ (0xAA >> (7 - i)) & 1 for i in range(8) ]
    # Rest (LEN | PAYLOAD | CRC)
    body = length + payload + crc
    body_bits = []
    for b in body:
        body_bits.extend([(b >> (7 - i)) & 1 for i in range(8)])

    bits = np.array(pre_bits + sync_bits + body_bits, dtype=np.int8)

    # ---- BFSK synth ----
    Nbit = int(round(BIT_DUR * SR))
    t = np.arange(Nbit) / SR
    tone0 = np.sin(2*np.pi*F0*t, dtype=np.float32)
    tone1 = np.sin(2*np.pi*F1*t, dtype=np.float32)

    # Concatenate per bit
    blocks = []
    for b in bits:
        blocks.append((tone1 if b else tone0))
    sig = AMP * np.concatenate(blocks).astype(np.float32)

    # Small silence tail
    tail = np.zeros(int(SR*0.10), dtype=np.float32)
    out = np.concatenate([sig, tail])

    # ---- Write WAV (no normalize) ----
    import soundfile as sf
    path = os.path.join(out_dir, "t3_snippet.wav")
    sf.write(path, out, SR, subtype="PCM_16")
    try: os.chmod(path, 0o644)
    except: pass
    print(f"[T3/BFSK] wrote {path}  (len={len(payload)} bytes)")


def build_t4(out_dir, token_ascii):
    os.makedirs(out_dir, exist_ok=True)

    # 1) two 8-byte nonces
    nonceA = os.urandom(8)
    nonceB = os.urandom(8)
    hushr1 = b"HUSHR" + nonceA
    hushr2 = b"HUSHR" + nonceB
    pcap_path = os.path.join(out_dir, "t4_hushr.pcap")
    write_udp_pcap(
        pcap_path,
        "10.0.0.10", "10.0.0.11", 50000, 50001,
        [hushr1, hushr2],
        start_ts=1_700_000_000.0, delta=0.02
    )

    # 2) KDF
    key16 = SHA256.new(nonceA + nonceB + b"PHR_KDF").digest()[:16]

    # 3) Encrypt token with AES-CTR; prefix 8-byte nonce used for CTR
    ctr_nonce = os.urandom(8)
    cipher = AES.new(key16, AES.MODE_CTR, nonce=ctr_nonce)
    ct = ctr_nonce + cipher.encrypt(token_ascii.encode("ascii"))

    # 4) LSB-embed into INT16 and write INT16 (NO float round-trip)
    carrier = sine_wave(440, 2.0, amplitude=0.20)
    # quantize once
    s16 = (np.clip(carrier, -1.0, 1.0) * 32767.0).round().astype(np.int16)
    bits = np.unpackbits(np.frombuffer(ct, dtype=np.uint8), bitorder="big")
    if bits.size > s16.size:
        raise ValueError("[T4] carrier too short for ciphertext")
    mod = s16.copy()
    mod[:bits.size] = (mod[:bits.size] & ~1) | bits

    # write INT16 directly
    wav_path = os.path.join(out_dir, "t4_hushr_clip.wav")
    sf.write(wav_path, mod, 44100, subtype="PCM_16")
    try: os.chmod(wav_path, 0o644)
    except: pass

    # (optional) self-check: re-read and confirm first bytes stable
    r, sr = sf.read(wav_path, dtype="int16", always_2d=False)
    if r.ndim: r = r.reshape(-1)
    chk = (r & 1).astype(np.uint8)[:bits.size]
    if np.packbits(chk, bitorder="big").tobytes()[:16] != ct[:16]:
        print("[T4] warning: LSB recheck mismatch in first 16 bytes (should be rare).")


def build_t5(out_dir, token_ascii, difficulty=None):
    """
    T5 with difficulty knobs.
    Produces:
      - t5_quartz_bundle.zip containing:
          * t5_s1.wav
          * t5_glyph.png  (atlas only; no token text)

    Difficulty modes:
      EASY   : Header @ known offset 1024, fixed hop=4, big-endian per symbol.
      MEDIUM : Header present; random start offset and hop (written in header), big-endian.
      HARD   : No header; hop + per-symbol bitorder keyed; start offset derived from RNG seeded by key16.
               (This mirrors the original hard puzzle: scan or reproduce keyed embedding.)

    Control via:
      - parameter `difficulty="EASY" | "MEDIUM" | "HARD"`
      - or env var PHR_T5_DIFFICULTY (overrides parameter if set)

    Header (EASY/MEDIUM only):
      MAGIC(8)='T5HDRv1!' |
      n_symbols(2,be) | bits_per(1) | hop(1) | start_bit(4,be) | reserved(4)=0
      All header bytes are embedded consecutively in LSB (1 bit per sample), big-endian per byte.
    """
    import io, base64, hashlib, math, os
    import numpy as np
    from Crypto.Hash import SHA256

    # -- pick difficulty
    d_env = os.environ.get("PHR_T5_DIFFICULTY", "").strip().upper()
    difficulty = d_env or (difficulty or "EASY")
    if difficulty not in {"EASY", "MEDIUM", "HARD"}:
        raise ValueError(f"Invalid difficulty '{difficulty}'. Choose EASY|MEDIUM|HARD")

    os.makedirs(out_dir, exist_ok=True)
    SR = 44100

    # 1) Atlas build (deterministic shuffle from token)
    alphabet = list("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-{}")
    seed = SHA256.new(token_ascii.encode() + b"::PHR_T4_ATLAS").digest()
    rng = np.random.default_rng(int.from_bytes(seed[:8], "big"))
    atlas = alphabet.copy()
    rng.shuffle(atlas)

    glyph_img = make_glyph_atlas(atlas, width=700, height=220, font_size=36,
                                 header="GLYPH ATLAS (ORDERED)")

    # 2) Payload string with CRC16 -> base32 suffix
    crc = crc16_ccitt_false(token_ascii.encode("ascii"))
    crc_b32 = base64.b32encode(crc.to_bytes(2, "big")).decode().rstrip("=")
    # Extract inner token for glyph encoding
    def unwrap(token: str) -> str:
        return token[5:-1] if token.startswith("PCCC{") and token.endswith("}") else token

    inner = unwrap(token_ascii)

    payload_text = (inner + "-" + crc_b32).upper()

    # map chars→indices in the shuffled atlas
    def to_indices(s: str) -> list[int]:
        out = []
        for ch in s:
            i = atlas.index(ch)  # raises if not present
            out.append(i)
        return out

    indices = to_indices(payload_text)
    n_symbols = len(indices)

    # 3) Key from PNG bytes (for masking and 'HARD' keyed embedding)
    buf = io.BytesIO(); glyph_img.save(buf, format="PNG"); png_bytes = buf.getvalue()
    key16 = hashlib.sha256(png_bytes + b"::PHR_T5_KEY").digest()[:16]

    # keystream for index masking (same for all modes)
    ks = stream_keystream(key16, n_symbols)
    masked = [ (idx + (ks[i] % len(atlas))) % len(atlas) for i, idx in enumerate(indices) ]

    # 4) Carrier
    def quantize_f32_to_i16(x):
        return np.round(np.clip(x, -1, 1) * 32767.0).astype(np.int16)

    # conservative duration calc
    bits_per = int(math.ceil(math.log2(len(atlas))))
    if difficulty in ("EASY", "MEDIUM"):
        # header bits + payload bits*hop + cushion
        # EASY fixed hop=4; MEDIUM hop random in [3..6], but we reserve the worst here.
        hop_plan = 4 if difficulty == "EASY" else 6
        est_bits = (16 * 8) + n_symbols * bits_per * hop_plan + 20000
        min_samples = est_bits + 10000
        dur = max(3.0, math.ceil(min_samples / SR) + 1)
        base = sine_wave(330, dur, amplitude=0.22)
        s16 = quantize_f32_to_i16(base)
    else:
        # HARD: we may need more room due to hops; still conservative
        est_bits = n_symbols * (bits_per + 4) * 6 + 30000
        min_samples = est_bits + 16000
        dur = max(3.0, math.ceil(min_samples / SR) + 1)
        base = sine_wave(330, dur, amplitude=0.22)
        s16 = quantize_f32_to_i16(base)

    # embedding helpers
    def embed_lsb_bytes_consecutive(int16_array, bit_start, raw_bytes):
        arr = int16_array
        bits = np.unpackbits(np.frombuffer(raw_bytes, dtype=np.uint8), bitorder="big")
        if bit_start + bits.size >= arr.size:
            raise ValueError("Header won't fit; increase duration.")
        seg = arr[bit_start : bit_start + bits.size]
        seg = (seg & ~1) | bits
        arr[bit_start : bit_start + bits.size] = seg
        return bit_start + bits.size

    def embed_symbols_fixed(arr_int16, bit_pos, sym_indices, bits_per, hop, big_endian=True):
        arr = arr_int16
        pos = bit_pos
        for val in sym_indices:
            if big_endian:
                bit_range = range(bits_per - 1, -1, -1)
            else:
                bit_range = range(bits_per)
            for b in bit_range:
                bit = (val >> b) & 1
                pos += hop
                if pos >= arr.size:
                    raise ValueError("Payload exceeded carrier; extend duration.")
                arr[pos] = (arr[pos] & ~1) | bit
        return pos

    # 5) Mode-specific embedding
    MAGIC = b"T5HDRv1!"  # 8 bytes

    if difficulty == "EASY" or difficulty == "Easy":
        hop = 4
        start_bit = 1024  # fixed & documented
        # Header: MAGIC | n_symbols(2) | bits_per(1) | hop(1) | start_bit(4) | reserved(4)=0
        header = (
            MAGIC
            + n_symbols.to_bytes(2, "big")
            + bytes([bits_per])
            + bytes([hop])
            + start_bit.to_bytes(4, "big")
            + b"\x00\x00\x00\x00"
        )
        next_bit = embed_lsb_bytes_consecutive(s16, start_bit, header)
        embed_symbols_fixed(s16, next_bit, masked, bits_per, hop, big_endian=True)

    elif difficulty == "MEDIUM" or difficulty == "Medium":
        # Header present, but start_bit and hop randomized and placed in the header
        rng_hdr = np.random.default_rng(int.from_bytes(key16, "big"))  # deterministic per PNG
        hop = int(rng_hdr.integers(3, 7))                # [3..6]
        start_bit = int(rng_hdr.integers(1024, 8192))    # randomized header placement
        header = (
            MAGIC
            + n_symbols.to_bytes(2, "big")
            + bytes([bits_per])
            + bytes([hop])
            + start_bit.to_bytes(4, "big")
            + b"\x00\x00\x00\x00"
        )
        next_bit = embed_lsb_bytes_consecutive(s16, start_bit, header)
        embed_symbols_fixed(s16, next_bit, masked, bits_per, hop, big_endian=True)

    else:  # HARD
        # No header. Hop and per-symbol bitorder are keyed; start offset derived from key.
        rng = np.random.default_rng(int.from_bytes(key16, "big"))
        # starting position (in bits) to begin payload
        start_bit = int(rng.integers(2048, 20000))
        pos = start_bit
        A = len(atlas)

        # keyed hop & per-symbol bitorder like your earlier hard mode
        for val in masked:
            # bitorder toggle (0=big,1=little)
            bitorder_little = (rng.integers(0, 2) == 1)
            if bitorder_little:
                bit_range = range(bits_per)                  # little-endian per symbol
            else:
                bit_range = range(bits_per - 1, -1, -1)      # big-endian per symbol
            for b in bit_range:
                hop = int(2 + rng.integers(0, 6))  # hops in [2..7]
                pos += hop
                if pos >= s16.size:
                    raise ValueError("Payload exceeded carrier; extend duration for HARD.")
                bit = (val >> b) & 1
                s16[pos] = (s16[pos] & ~1) | bit

    # 6) Save artifacts
    t5_wav_path = os.path.join(out_dir, "t5_s1.wav")
    import soundfile as sf
    sf.write(t5_wav_path, s16, SR, subtype="PCM_16")

    t5_png_path = os.path.join(out_dir, "t5_glyph.png")
    glyph_img.save(t5_png_path)

    # Uncommented 
    
    zip_path = os.path.join(out_dir, "t5_quartz_bundle.zip")
    import zipfile
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as z:
        z.write(t5_wav_path, arcname="t5_s1.wav")
        z.write(t5_png_path, arcname="t5_glyph.png")

    for p in (t5_wav_path, t5_png_path, zip_path):
        try: os.chmod(p, 0o644)
        except: pass

    print(f"[T5:{difficulty}] symbols={n_symbols} bits/sym={bits_per}")



def main(out_dir):
    os.makedirs(out_dir, exist_ok=True)
    toks = tokens_from_env()
    build_t1(out_dir, toks['T1'])
    build_t2(out_dir, toks['T2'])
    build_t3(out_dir, toks['T3'])
    build_t4(out_dir, toks['T4'])
    build_t5(out_dir, toks['T5'], difficulty="MEDIUM")
    tarpath = os.path.join(out_dir, 'evidence_collection.tar.gz')
    with tarfile.open(tarpath, "w:gz") as tar:
        for fn in os.listdir(out_dir):
            if fn.endswith('.tar.gz'): continue
            tar.add(os.path.join(out_dir, fn), arcname=fn)
    print("[web] Evidence generated successfully.")

if __name__ == "__main__":
    import os, argparse
    p=argparse.ArgumentParser(); p.add_argument("--out", required=True); a=p.parse_args()
    main(a.out)
