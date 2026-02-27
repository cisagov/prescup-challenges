#!/usr/bin/env python3
"""
Brute-force all 256 XOR keys against a carved binary blob
from mem.strings. Prints any plausible ASCII output.
"""

import sys, string

def score(candidate: bytes) -> int:
    """Return a score based on how printable/token-like the text looks."""
    try:
        text = candidate.decode("utf-8")
    except UnicodeDecodeError:
        return 0
    # Heuristic: must be mostly printable
    if all(c in string.printable for c in text):
        # bonus if it looks like a flag
        if text.startswith("PCCC{") and text.endswith("}"):
            return 999
        return len([c for c in text if c in string.ascii_letters + "{}_"])
    return 0

def brute(blob: bytes):
    best = None
    for key in range(256):
        out = bytes(b ^ key for b in blob)
        s = score(out)
        if s > 0:
            text = ""
            try:
                text = out.decode("utf-8")
            except: pass
            print(f"[key=0x{key:02x}] {text}")
            if s == 999:
                best = (key, text)
    if best:
        print("\n*** Likely token recovered! ***")
        print(f"Key = 0x{best[0]:02x}, Token = {best[1]}")

if __name__ == "__main__":
    data = sys.stdin.buffer.read()
    if not data:
        sys.exit("Usage: dd if=mem.strings bs=1 skip=<HEX KEY - 0xXX> count=16 | python3 xor_bruter.py")
    brute(data)