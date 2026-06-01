# ctfcrypto.py
# Custom lightweight crypto primitives used by the challenge
# Contains:
# - Tiny ARX-inspired permutation (`permute_block`)
# - xorshift-ish PRNG producing keystream bytes (`TinyPRNG`)
# These are intentionally non-standard but moderately cryptographically subtle.

from typing import List
import struct

def rol32(x, r):
    return ((x << r) & 0xffffffff) | (x >> (32 - r))

def ror32(x, r):
    return ((x >> r) | ((x << (32 - r)) & 0xffffffff)) & 0xffffffff

def permute_block(v0: int, v1: int, rounds: int = 8):
    """
    Tiny ARX-like 64-bit permutation on two 32-bit words.
    Not a standard cipher. Deterministic and reversible if rounds known.
    Used to derive block-level mixing for the challenge.
    """
    for i in range(rounds):
        v0 = (v0 + rol32(v1 ^ 0x9e3779b9, (i & 31))) & 0xffffffff
        v1 = (v1 + rol32(v0 ^ 0x7f4a7c15, ((i*3) & 31))) & 0xffffffff
        v0 ^= (v1 << ((i+1)&7)) & 0xffffffff
        v1 ^= ror32(v0, (i & 7))
    return v0 & 0xffffffff, v1 & 0xffffffff

class TinyPRNG:
    """
    Small xorshift-derived 128-bit state PRNG producing bytes.
    Designed so that small contiguous output leaks give limited info,
    but with enough samples it's recoverable using advanced techniques.
    """
    def __init__(self, seed_bytes: bytes):
        # seed bytes -> four 32-bit words
        if len(seed_bytes) < 16:
            seed_bytes = seed_bytes.ljust(16, b'\x00')
        self.state = list(struct.unpack("<4I", seed_bytes[:16]))

    def next_u32(self):
        s0, s1, s2, s3 = self.state
        # xorshift variant
        t = (s0 ^ (s0 << 11)) & 0xffffffff
        s0 = s1
        s1 = s2
        s2 = s3
        s3 = (s3 ^ (s3 >> 19) ^ (t ^ (t >> 8))) & 0xffffffff
        self.state = [s0, s1, s2, s3]
        return s3

    def keystream(self, nbytes: int):
        out = bytearray()
        while len(out) < nbytes:
            x = self.next_u32()
            out += struct.pack("<I", x)
        return bytes(out[:nbytes])

# convenience simple XOR stream cipher using TinyPRNG keystream
def xs_stream_encrypt(plain: bytes, seed: bytes):
    pr = TinyPRNG(seed)
    ks = pr.keystream(len(plain))
    return bytes([p ^ k for p,k in zip(plain, ks)])

def xs_stream_decrypt(ct: bytes, seed: bytes):
    return xs_stream_encrypt(ct, seed)  # symmetric
