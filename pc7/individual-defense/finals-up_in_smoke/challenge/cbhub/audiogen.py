import math
import os
import random
import struct
import wave
from typing import List

ALPH36 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"

# Frequencies used by the legacy beacon (Hz), ordered low->high.
DIGIT_FREQS = [700, 900, 1100, 1300, 1700, 1900]
PREAMBLE_HZ = 1500

def _base36_pairs(code: str) -> List[int]:
    pairs = []
    for ch in code:
        v = ALPH36.index(ch)
        pairs.append(v // 6)
        pairs.append(v % 6)
    return pairs

def _checksum_digit(digits: List[int]) -> int:
    # Simple non-cryptographic check digit (mod-6), for realism.
    s = 0
    for i, d in enumerate(digits):
        s = (s + (d + 1) * (i + 3)) % 97
    return s % 6

def generate_handshake_wav(
    out_path: str,
    *,
    code12: str,
    seed: int = 777,
    sample_rate: int = 44100,
    tone_ms: int = 40,
    gap_ms: int = 10,
    preamble_ms: int = 520,
    amp: float = 0.55,
    noise_amp: float = 0.010,
    jitter_hz: float = 12.0,
):
    """
    Generate a CB-style provisioning beacon.

    Design goals:
    - decodable with basic FFT tooling
    - noisy enough to require real analysis (not just eyeballing raw bytes)
    - deterministic under a seed (for reproducibility in maintainer debugging)
    """
    rng = random.Random(seed)

    digits = _base36_pairs(code12)
    digits.append(_checksum_digit(digits))

    def tone(freq: float, ms: int) -> List[int]:
        # Slight frequency jitter per symbol (still within solvable tolerance).
        f = float(freq) + rng.uniform(-jitter_hz, jitter_hz)
        n = int(sample_rate * (ms / 1000.0))
        out = []
        for i in range(n):
            t = i / float(sample_rate)
            s = math.sin(2.0 * math.pi * f * t)
            # Add small gaussian noise
            s += rng.gauss(0.0, noise_amp)
            v = int(max(-1.0, min(1.0, s * amp)) * 32767)
            out.append(v)
        return out

    def silence(ms: int) -> List[int]:
        n = int(sample_rate * (ms / 1000.0))
        out = []
        for _ in range(n):
            s = rng.gauss(0.0, noise_amp * 0.6)
            v = int(max(-1.0, min(1.0, s)) * 32767)
            out.append(v)
        return out

    pcm: List[int] = []
    # lead-in silence
    pcm += silence(120)
    # preamble
    pcm += tone(PREAMBLE_HZ, preamble_ms)
    pcm += silence(80)

    for d in digits:
        pcm += tone(DIGIT_FREQS[d], tone_ms)
        pcm += silence(gap_ms)

    # tail
    pcm += silence(250)

    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with wave.open(out_path, "wb") as w:
        w.setnchannels(1)
        w.setsampwidth(2)  # int16
        w.setframerate(sample_rate)
        w.writeframes(struct.pack("<" + "h" * len(pcm), *pcm))
