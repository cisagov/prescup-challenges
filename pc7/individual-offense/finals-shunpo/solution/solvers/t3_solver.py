#!/usr/bin/env python3
import gzip
import json
from pathlib import Path

config = json.loads(Path("artifacts/device_config.json").read_text())
seed_high = int(Path("artifacts/key_part_a.txt").read_text().split("Value : ")[1].strip(), 16)
seed_low = int(Path("artifacts/key_part_b.txt").read_text().split("Value : ")[1].strip(), 16)
mult = int(config["crypto"]["multiplier"], 16)
inc = int(config["crypto"]["increment"], 16)

seed = (seed_high << 16) | seed_low
state = seed
ciphertext = Path("files/update.bin.enc").read_bytes()
keystream = bytearray()

for _ in range(len(ciphertext)):
    state = (state * mult + inc) & 0xffffffff
    keystream.append((state >> 16) & 0xff)

plaintext = bytes(c ^ k for c, k in zip(ciphertext, keystream))
print(gzip.decompress(plaintext).decode())