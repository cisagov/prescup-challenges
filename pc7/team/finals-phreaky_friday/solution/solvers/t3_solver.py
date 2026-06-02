```python
#!/usr/bin/env python3
"""
Simple BFSK decoder for Token 3 (T3)
Usage: python3 t3_solver.py t3_snipper.wav

Requires: numpy, soundfile
Install: pip install numpy soundfile
"""
import sys
import numpy as np
import soundfile as sf

# ---------- Parameters (adjust if bundle differs) ----------
F0 = 1500.0           # frequency for bit 0 (Hz)
F1 = 2300.0           # frequency for bit 1 (Hz)
BIT_RATE = 25.0       # symbols per second
PREAMBLE_BITS = 32    # preamble length in bits (0x55 pattern repeated)
SYNC_WORD = 0xDDAA    # sync word (16 bits)

# -----------------------------------------------------------

def goertzel_power(x, sr, freq):
    """Return the (scaled) power at `freq` in signal `x` (1-D numpy array).
    Implementation of Goertzel algorithm (real-valued power).
    """
    n = x.size
    k = int(0.5 + (n * freq) / sr)
    omega = (2.0 * np.pi * k) / n
    coeff = 2.0 * np.cos(omega)
    s_prev = 0.0
    s_prev2 = 0.0
    for sample in x:
        s = sample + coeff * s_prev - s_prev2
        s_prev2 = s_prev
        s_prev = s
    power = s_prev2 * s_prev2 + s_prev * s_prev - coeff * s_prev * s_prev2
    return float(power)


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


def bits_to_bytes(bits):
    # bits is iterable of 0/1, MSB-first per byte
    arr = np.array(bits, dtype=np.uint8)
    nbytes = len(arr) // 8
    if nbytes == 0:
        return b""
    arr = arr[: nbytes * 8].reshape((nbytes, 8))
    out = np.packbits(arr, axis=1, bitorder='big')
    return out.flatten().tobytes()


def find_sync(byte_stream):
    # search for SYNC word sequence inside bytes; return index of sync's first byte or -1
    for i in range(len(byte_stream)-1):
        if byte_stream[i] == ((SYNC_WORD >> 8) & 0xFF) and byte_stream[i+1] == (SYNC_WORD & 0xFF):
            return i
    return -1


def main(argv):
    if len(argv) < 2:
        print("Usage: decode_t3_bfsk.py t3_fsk.wav")
        return
    wav_path = argv[1]
    data, sr = sf.read(wav_path)
    if data.ndim > 1:
        data = data[:,0]
    data = data.astype(np.float32)

    bit_dur = 1.0 / BIT_RATE
    window_n = int(round(sr * bit_dur))
    if window_n < 16:
        raise SystemExit("ERROR: window too small, adjust BIT_RATE or sample rate")

    # slice into windows
    n_windows = len(data) // window_n
    bits = []
    for w in range(n_windows):
        seg = data[w*window_n : (w+1)*window_n]
        p0 = goertzel_power(seg, sr, F0)
        p1 = goertzel_power(seg, sr, F1)
        bits.append(1 if p1 > p0 else 0)

    # We expect preamble then sync. Search for preamble pattern 0x55 repeated
    # Build a bytes stream (MSB-first per byte)
    bstream = bits_to_bytes(bits)
    if not bstream:
        print("No bits recovered — check BIT_RATE and sample rate.")
        return

    # find SYNC
    sync_idx = find_sync(bstream)
    if sync_idx < 0:
        print("SYNC not found in recovered bytes. Try scanning for different bit offset or inspect preamble visually.")
        # helpful diagnostic: print first 64 bytes hex
        print("first bytes (hex):", bstream[:64].hex())
        return

    # parse after sync
    pos = sync_idx + 2
    if pos >= len(bstream):
        print("Truncated after sync")
        return
    length = bstream[pos]
    pos += 1
    if pos + length + 2 > len(bstream):
        print("Truncated payload; available bytes too small")
        return
    payload = bstream[pos:pos+length]
    crc_read = int.from_bytes(bstream[pos+length:pos+length+2], 'big')

    crc_calc = crc16_ccitt_false(bytes([length]) + payload)

    print("Recovered payload bytes:", payload)
    try:
        print("Payload (ASCII):", payload.decode('ascii'))
    except Exception:
        print("Payload not printable ASCII")
    print(f"CRC read:  0x{crc_read:04X}")
    print(f"CRC calc:  0x{crc_calc:04X}")
    if crc_calc == crc_read:
        print('\n=== SUCCESS: CRC OK. Token appears in payload ===')
    else:
        print('\nWARNING: CRC mismatch — payload may be corrupted or parameters wrong')

if __name__ == '__main__':
    main(sys.argv)