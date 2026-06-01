# extract_t1_lsb_token.py
import numpy as np
import soundfile as sf

WAV = "t1_calldata_recovered.wav"

def main():
    data, sr = sf.read(WAV)
    # Ensure 1-D
    if data.ndim > 1:
        data = data[:,0]
    # Match the embedding math: int16 grid
    ints = np.int16(np.round(np.clip(data, -1.0, 1.0) * 32767.0))
    bits = (ints & 1).astype(np.uint8)

    # Pack as big-endian per byte (that’s how it was embedded)
    nbytes = (len(bits) // 8)
    bits = bits[: nbytes*8]
    by = np.packbits(bits.reshape(-1,8), bitorder="big").tobytes()

    # Token is null-terminated ASCII
    token = by.split(b"\x00", 1)[0]
    try:
        print(token.decode("ascii"))
    except UnicodeDecodeError:
        print("[!] Got non-ASCII; likely wrong input WAV or LSB got mangled.")
        print("Raw bytes:", token)

if __name__ == "__main__":
    main()