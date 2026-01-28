import struct, zlib, hashlib

with open("<YOUR FILE NAME>", "rb") as f: # Replace accordingly
    blob = f.read()

magic = blob[:4]
tag   = blob[4:8]
ln    = struct.unpack("<I", blob[8:12])[0]
obf   = blob[12:12+ln]
crc   = struct.unpack("<I", blob[12+ln:16+ln])[0]

assert magic == b"DD1\x01", f"Bad magic: {magic!r}"
assert zlib.crc32(obf) & 0xffffffff == crc, "CRC mismatch (wrong slice / corrupted data)"

# MUST match builder:
SEED_STR = "DARKHORSE_HORIZON_21pN" # replace with your seed
KEY_BYTES = hashlib.blake2s(SEED_STR.encode("utf-8"), digest_size=32).digest()

def keystream(key: bytes, n: int) -> bytes:
    out = bytearray()
    counter = 0
    while len(out) < n:
        h = hashlib.blake2s(key=key, digest_size=32)
        h.update(struct.pack("<I", counter))
        out.extend(h.digest())
        counter += 1
    return bytes(out[:n])

ks = keystream(KEY_BYTES, len(obf))
pt = bytes(a ^ b for a, b in zip(obf, ks))

print("tag:", tag.decode(errors="replace"))
print("len:", ln)
print("plaintext:", pt.decode(errors="replace"))