#!/usr/bin/env python3
import socket

def compute_base_from_implant(hostname: str) -> int:
    """
    Resolve the implant hostname (e.g. null-horizon.local) and compute:
        BASE = (sum(IP bytes) ^ 0xA5) & 0xFF
    where IP bytes are the 4 bytes of the IPv4 address.
    """
    ip_str = socket.gethostbyname(hostname)   # e.g. "10.5.5.50"
    ip_bytes = socket.inet_aton(ip_str)       # b'\x0a\x05\x05\x32'
    s = sum(ip_bytes)
    base = (s ^ 0xA5) & 0xFF
    return base

def decode_frames(cipher_hex: str, hostname: str = "null-horizon.local") -> str:
    """
    Decode the hex-encoded control frames blob using:
        P[i] = C[i] XOR ((BASE + i) mod 256)
    """
    cipher = bytes.fromhex(cipher_hex)
    base = compute_base_from_implant(hostname)

    out = bytearray()
    for i, c in enumerate(cipher):
        key = (base + i) & 0xFF
        out.append(c ^ key)

    return out.decode(errors="replace")

if __name__ == "__main__":
    # This hex string is what you publish in the SPEC or via a download command.
    FRAMES_HEX = "REPLACE ME"  # <-- REPLACE with your real encoded frames from the download frames function (e.g. the HEX value you received from 'download frames'.)

    pt = decode_frames(FRAMES_HEX, "null-horizon.local")
    print("Decoded frames plaintext:", repr(pt))