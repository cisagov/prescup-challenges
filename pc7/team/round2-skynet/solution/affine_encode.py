#!/usr/bin/env python3

#affine_encode.py

import argparse

A = 5
B = 0x22

def affine256_encode(data: bytes) -> bytes:
    return bytes(((A * b + B) & 0xFF) for b in data)

def main():
    ap = argparse.ArgumentParser(description="Affine256 encode UTF-8 text to hex")
    ap.add_argument("text", help='plaintext, e.g. "Skynet"')
    args = ap.parse_args()

    pt = args.text.encode("utf-8")
    ct = affine256_encode(pt)

    hexstr = ct.hex()

    print("plaintext:", args.text)
    print("utf8 bytes:", pt.hex())
    print("cipher hex:", hexstr)

if __name__ == "__main__":
    main()
