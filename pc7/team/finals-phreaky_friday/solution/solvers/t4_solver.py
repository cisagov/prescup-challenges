#!/usr/bin/env python3
# t4_solver.py
# Extracts HUSHR nonces from pcap and decrypts LSB-embedded ciphertext in WAV.

import argparse, re, sys, os
import numpy as np, soundfile as sf
from scapy.all import rdpcap, Raw
from Crypto.Hash import SHA256
from Crypto.Cipher import AES

def extract_nonces(pcap_path):
    pkts = rdpcap(pcap_path)
    return [bytes(p[Raw].load)[5:13] for p in pkts if Raw in p and bytes(p[Raw].load).startswith(b"HUSHR")]

def derive_key(a,b):
    return SHA256.new(a+b+b"PHR_KDF").digest()[:16]

def read_lsb_bits(path):
    s, sr = sf.read(path, dtype='int16')
    ints = np.int16(s).flatten()
    return (ints & 1).astype(np.uint8), sr

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--pcap', default='t4_hushr.pcap')
    ap.add_argument('--wav', default='t4_hushr_clip.wav')
    args = ap.parse_args()

    nonceA, nonceB = extract_nonces(args.pcap)
    key = derive_key(nonceA, nonceB)
    print("[i] Derived key:", key.hex())

    bits, sr = read_lsb_bits(args.wav)
    ct = np.packbits(bits, bitorder='big').tobytes().rstrip(b"\x00")
    nonce = ct[:8]
    data = ct[8:]
    cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
    pt = cipher.decrypt(data)
    print("[+] Plaintext:", pt)

if __name__ == "__main__":
    main()