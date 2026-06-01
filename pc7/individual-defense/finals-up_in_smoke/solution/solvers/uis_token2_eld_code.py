#!/usr/bin/env python3
"""
uis_token2_eld_code.py

Robust decoder for the CB Hub handshake audio used to recover the
12-character ELD unlock code for Token 2.

What it does:
- Reads a WAV file (default: handshake.wav)
- Detects the tone sequence using FFT
- Removes silence markers and leading preamble tones
- Separates data digits from the final checksum digit
- Decodes 24 base-6 data digits into a 12-character base-36 unlock code
- Optionally validates the checksum

Usage:
    python3 uis_token2_eld_code.py handshake.wav
    python3 uis_token2_eld_code_fixed.py /path/to/handshake.wav --verbose
"""

from __future__ import annotations

import argparse
import sys
import wave
from pathlib import Path

import numpy as np

TONE_LEN_MS = 40
GAP_LEN_MS = 10
PREAMBLE_HZ = 1500

# Symbol tones from the challenge protocol
TONES = {
    700: "A",
    900: "B",
    1100: "C",
    1300: "D",
    1500: "P",  # preamble
    1700: "E",
    1900: "F",
}

ALPHABET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
DIGIT = {"A": 0, "B": 1, "C": 2, "D": 3, "E": 4, "F": 5}


def checksum_digit(digits: list[int]) -> int:
    s = 0
    for i, d in enumerate(digits):
        s = (s + (d + 1) * (i + 3)) % 97
    return s % 6


def peak_frequency(seg: np.ndarray, fs: int) -> float:
    win = np.hanning(len(seg))
    spectrum = np.fft.rfft(seg * win)
    mags = np.abs(spectrum)

    if len(mags) <= 1:
        return 0.0

    k = int(np.argmax(mags[1:]) + 1)
    return k * fs / len(seg)


def load_wav(path: Path) -> tuple[np.ndarray, int]:
    with wave.open(str(path), "rb") as w:
        fs = w.getframerate()
        n = w.getnframes()
        channels = w.getnchannels()
        sample_width = w.getsampwidth()
        raw = w.readframes(n)

    if sample_width != 2:
        raise ValueError(f"expected 16-bit PCM WAV, got sample width {sample_width}")

    x = np.frombuffer(raw, dtype=np.int16).astype(np.float32)

    if channels > 1:
        x = x.reshape(-1, channels).mean(axis=1)

    x = x / 32768.0
    return x, fs


def _find_data_start(x: np.ndarray, fs: int) -> int:
    """
    Locate the first data tone by anchoring off the preamble.

    Strategy: slide a short analysis window, find the longest contiguous run
    of ~1500 Hz (the preamble), then scan forward past the silence gap to
    the first data tone.
    """
    win_samples = int(fs * 0.020)  # 20 ms analysis window
    hop = int(fs * 0.005)          # 5 ms hop
    min_preamble_windows = 10      # require at least ~200ms of preamble

    # Classify each window as preamble or not.
    is_preamble = []
    positions = []
    for pos in range(0, len(x) - win_samples, hop):
        seg = x[pos : pos + win_samples]
        f = peak_frequency(seg, fs)
        is_preamble.append(abs(f - PREAMBLE_HZ) <= 80)
        positions.append(pos)

    # Find the longest contiguous run of preamble windows.
    best_run_start = -1
    best_run_len = 0
    run_start = -1
    run_len = 0
    for i, is_p in enumerate(is_preamble):
        if is_p:
            if run_start < 0:
                run_start = i
                run_len = 1
            else:
                run_len += 1
            if run_len > best_run_len:
                best_run_len = run_len
                best_run_start = run_start
        else:
            run_start = -1
            run_len = 0

    if best_run_len < min_preamble_windows:
        return 0  # fallback

    preamble_end = positions[best_run_start + best_run_len - 1] + win_samples

    # The generator always inserts an 80 ms silence gap after the preamble.
    # Use that to estimate the data start, then fine-tune by scanning for
    # the first high-energy window that aligns with a data tone.
    gap_samples = int(fs * 0.080)
    estimated_data_start = preamble_end + gap_samples

    tone_len = int(fs * (TONE_LEN_MS / 1000.0))
    # Search ±20 ms around the estimate for the best tone alignment.
    margin = int(fs * 0.020)
    lo = max(0, estimated_data_start - margin)
    hi = min(len(x) - tone_len, estimated_data_start + margin)

    best_pos = estimated_data_start
    best_rms = 0.0
    for pos in range(lo, hi):
        seg = x[pos : pos + tone_len]
        rms = float(np.sqrt(np.mean(seg ** 2)))
        if rms > best_rms:
            best_rms = rms
            best_pos = pos

    return best_pos


def decode_symbol_stream(x: np.ndarray, fs: int) -> tuple[str, int]:
    tone_len = int(fs * (TONE_LEN_MS / 1000.0))
    step = int(fs * ((TONE_LEN_MS + GAP_LEN_MS) / 1000.0))

    if tone_len <= 0 or step <= 0 or len(x) < tone_len:
        raise ValueError("audio too short to decode")

    data_start = _find_data_start(x, fs)

    # Decode directly from the detected data start.
    syms: list[str] = []
    nframes = (len(x) - data_start) // step

    for i in range(nframes):
        start = data_start + i * step
        seg = x[start : start + tone_len]
        if len(seg) < tone_len:
            break

        f = peak_frequency(seg, fs)
        nearest = min(TONES.keys(), key=lambda t: abs(f - t))

        if abs(f - nearest) <= 60:
            syms.append(TONES[nearest])
        else:
            syms.append("?")

    return "".join(syms), data_start


def extract_payload(seq: str) -> str:
    # The decoder starts directly at the data region (after preamble),
    # so the stream should be data symbols (A-F) with possible trailing
    # noise (?, stray P). Keep only data symbols and take the first 25
    # (24 data digits + 1 checksum).
    payload = "".join(c for c in seq if c in "ABCDEF")

    if len(payload) > 25:
        payload = payload[:25]

    return payload

def decode_unlock_code(payload: str) -> tuple[str, int, int]:
    bad = [c for c in payload if c not in DIGIT]
    if bad:
        raise ValueError(f"payload contains unexpected symbols: {''.join(sorted(set(bad)))}")

    payload_digits = [DIGIT[c] for c in payload]

    if len(payload_digits) < 3:
        raise ValueError("payload too short to contain data plus checksum")

    check_digit = payload_digits[-1]
    data_digits = payload_digits[:-1]

    if len(data_digits) != 24:
        raise ValueError(
            f"expected 24 data digits for a 12-character code, got {len(data_digits)}"
        )

    if len(data_digits) % 2 != 0:
        raise ValueError(f"odd number of data digits recovered: {len(data_digits)}")

    pairs = [data_digits[i] * 6 + data_digits[i + 1] for i in range(0, len(data_digits), 2)]

    if any(p >= len(ALPHABET) for p in pairs):
        raise ValueError("decoded pair outside base-36 range")

    code = "".join(ALPHABET[p] for p in pairs)
    calc_check = checksum_digit(data_digits)
    return code, check_digit, calc_check


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("wav", nargs="?", default="handshake.wav", help="path to WAV file")
    parser.add_argument("--verbose", action="store_true", help="print intermediate decode details")
    args = parser.parse_args()

    wav_path = Path(args.wav)
    if not wav_path.exists():
        print(f"error: file not found: {wav_path}", file=sys.stderr)
        return 1

    try:
        x, fs = load_wav(wav_path)
        seq, offset = decode_symbol_stream(x, fs)
        payload = extract_payload(seq)
        code, seen_check, calc_check = decode_unlock_code(payload)
    except Exception as e:
        print(f"decode failed: {e}", file=sys.stderr)
        return 2

    if args.verbose:
        print(f"file: {wav_path}")
        print(f"sample_rate: {fs}")
        print(f"best_offset: {offset}")
        print(f"symbols: {seq}")
        print(f"payload: {payload}")
        print(f"checksum seen: {seen_check}")
        print(f"checksum calc: {calc_check}")
        print(f"checksum ok: {seen_check == calc_check}")

    print(f"UNLOCK CODE: {code}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())