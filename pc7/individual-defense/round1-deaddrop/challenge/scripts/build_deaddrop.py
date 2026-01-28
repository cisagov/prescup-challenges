import os
import subprocess
import secrets
import shutil
from pathlib import Path
from PIL import Image
import base64
import random
import hashlib
import struct
import zlib

BASE = Path("/challenge")
DISK_IMG = BASE / "dead_drop.img"
CONTAINER_IMGS = [BASE / f"enc_{c}.img" for c in "abcd"]
ZIP_CONTAINERS = [BASE / f"enc_{c}.zip" for c in "abcd"]
TOKENS = [os.environ[f"TOKEN{i}"] for i in range(1, 5)]
FRAGS = [secrets.token_hex(8) for _ in range(4)]
STEGO_PASS = "".join(FRAGS)
TOKEN5 = os.environ.get("TOKEN5")
FINAL_FLAG = f"TOKEN5: {TOKEN5} - 💥 You are the mole. 💥"
WWW = Path("/var/www/html")
WWW.mkdir(parents=True, exist_ok=True)
SEED = os.environ.get("SEED").encode("utf-8")
KEY_SEED = hashlib.blake2s(SEED, digest_size=32).digest()

# Helpers

RECORD_MAGIC = b"DD1\x01"  # stable carving signature

def _keystream(key: bytes, n: int) -> bytes:
    out = bytearray()
    counter = 0
    while len(out) < n:
        h = hashlib.blake2s(key=key, digest_size=32)
        h.update(struct.pack("<I", counter))
        out.extend(h.digest())
        counter += 1
    return bytes(out[:n])

def _xor(data: bytes, key: bytes) -> bytes:
    ks = _keystream(key, len(data))
    return bytes(d ^ k for d, k in zip(data, ks))

def pack_record(tag4: bytes, plaintext: bytes, key: bytes) -> bytes:
    if len(tag4) != 4:
        raise ValueError("tag must be 4 bytes, e.g. b'TK03'")
    obf = _xor(plaintext, key)
    crc = zlib.crc32(obf) & 0xFFFFFFFF
    return RECORD_MAGIC + tag4 + struct.pack("<I", len(obf)) + obf + struct.pack("<I", crc)


def run(cmd, **kwargs):
    print(">", " ".join(str(x) for x in cmd))
    return subprocess.run(cmd, check=True, **kwargs)
    
def png_to_jpg(png_path, jpg_path):
    img = Image.open(png_path)
    rgb = img.convert('RGB')
    rgb.save(jpg_path, "JPEG", quality=95)

def create_fat_img(img_path, size_mb, fat_type=None):
    if img_path.exists():
        img_path.unlink()
    run(["dd", "if=/dev/zero", f"of={img_path}", "bs=1M", f"count={size_mb}"])
    if not fat_type:
        fat_type = "16" if size_mb >= 16 else "12"
    run(["mkfs.fat", "-F", fat_type, str(img_path)])

def mcopy(img, src, dst_in_img):
    run(["mcopy", "-i", str(img), str(src), dst_in_img])

def mdel(img, filename_in_img):
    run(["mdel", "-i", str(img), filename_in_img])

def lsb_hide_token(img_in, img_out, token):
    img = Image.open(img_in).convert('RGB')
    pixels = img.load()
    width, height = img.size

    # Prepare the data: token as binary string + end marker
    data = ''.join([format(ord(c), '08b') for c in token])
    data += '00000000' * 2  # Use two null bytes as an end marker

    data_idx = 0
    total_bits = len(data)
    for y in range(height):
        for x in range(width):
            if data_idx >= total_bits:
                img.save(img_out)
                return
            r, g, b = pixels[x, y]
            # Replace LSB of R, G, B with up to 3 bits of data
            rgb = []
            for color in (r, g, b):
                if data_idx < total_bits:
                    bit = int(data[data_idx])
                    color = (color & ~1) | bit
                    data_idx += 1
                rgb.append(color)
            pixels[x, y] = tuple(rgb)
    img.save(img_out)

def hide_token_in_png_lsb(img, token):
    decoy = BASE / "decoy.png"
    shutil.copy(BASE / "dead_drop.png", decoy)
    decoy_with_token = BASE / "the_second_mirage.png"
    lsb_hide_token(decoy, decoy_with_token, token)
    mcopy(img, decoy_with_token, "::/the_second_mirage.png")
    decoy.unlink()
    decoy_with_token.unlink()


# Token 3
def hide_token_raw_sector(img, token):
    key = KEY_SEED
    rec = pack_record(b"TK03", token.encode(), key)

    with open(img, "r+b") as f:
        f.seek(0x4000)
        f.write(rec)


# Token 4
def hide_token_as_obfuscated_comment(img, token):
    key = KEY_SEED
    rec = pack_record(b"TK04", token.encode(), key)

    temp = BASE / "OP_DARKHORSE.dat"
    with open(temp, "wb") as f:
        f.write(secrets.token_bytes(64))
        f.write(rec)
        f.write(secrets.token_bytes(64))

    mcopy(img, temp, "::/OP_DARKHORSE.dat")
    temp.unlink()


def steghide_embed_token(jpg_path, passphrase, flag):
    temp_flag = BASE / "finaltoken.txt"
    with open(temp_flag, "w") as f:
        f.write(flag)
    run([
        "steghide", "embed", "-ef", str(temp_flag), "-cf", str(jpg_path),
        "-p", passphrase, "-Z"
    ])
    temp_flag.unlink()

def make_container_zip(container_img, zip_path, password, key_frag):
    create_fat_img(container_img, 3)  # Small image, 3MB
    # Drop fragment.txt inside
    fragfile = BASE / "fragment.txt"
    with open(fragfile, "w") as f:
        f.write(key_frag)
    mcopy(container_img, fragfile, "::/fragment.txt")
    fragfile.unlink()
    # Now zip it with password
    if zip_path.exists():
        zip_path.unlink()
    run(["zip", "-j", "-P", password, str(zip_path), str(container_img)])
    container_img.unlink()  # Clean up .img (only .zip is distributed)

# Token 1 re-logic
def hide_token_deleted_file(img, token):
    key = KEY_SEED
    rec = pack_record(b"TK01", token.encode(), key)

    temp = BASE / "old_token.bin"
    with open(temp, "wb") as f:
        f.write(secrets.token_bytes(32))
        f.write(rec)
        f.write(secrets.token_bytes(32))

    mcopy(img, temp, "::/old_token.bin")
    mdel(img, "::/old_token.bin")
    temp.unlink()

def main():
    # 0. Make parent disk image
    create_fat_img(DISK_IMG, 100)
    
    # 1. Convert PNG TO JPG, embed stego flag, copy to image
    flag_jpg_path = BASE / "dead_drop_for_embed.jpg"
    png_to_jpg(BASE / "dead_drop.png", flag_jpg_path)
    steghide_embed_token(flag_jpg_path, STEGO_PASS, FINAL_FLAG)
    mcopy(DISK_IMG, flag_jpg_path, "::/dead_drop.jpg")
    flag_jpg_path.unlink()
    
    # 2. Make and zip containers
    for i in range(4):
        make_container_zip(CONTAINER_IMGS[i], ZIP_CONTAINERS[i], TOKENS[i], FRAGS[i])
        mcopy(DISK_IMG, ZIP_CONTAINERS[i], f"::/{ZIP_CONTAINERS[i].name}")
        ZIP_CONTAINERS[i].unlink()

    # 3. Hide tokens for forensics (TOKEN2, TOKEN3, TOKEN4)
    hide_token_in_png_lsb(DISK_IMG, TOKENS[1])     # TOKEN2
    hide_token_raw_sector(DISK_IMG, TOKENS[2])          # TOKEN3
    hide_token_as_obfuscated_comment(DISK_IMG, TOKENS[3])  # TOKEN4 (obfuscated)

    # 4. LAST: Hide deleted file with TOKEN1 for recovery
    hide_token_deleted_file(DISK_IMG, TOKENS[0])        # TOKEN1

    # 5. Copy for Apache
    shutil.copy(DISK_IMG, WWW / "dead_drop.img")
    shutil.copy(BASE / "dead_drop.png", WWW / "dead_drop.png")
    with open(WWW / "mission_briefing.txt", "w") as f:
        f.write(f"""\

        [TOP SECRET - EYES ONLY]
        >>> OPERATION: DEAD DROP
        >>> AGENT: ZERO
        >>> OBJECTIVE: RECOVER THE HIDDEN TOKENS AND COMBINE THEM TO IDENTIFY THE INTERNAL THREAT.
        >>> METHODS: ADVANCED DISK FORENSICS, MULTI-LAYER DECRYPTION.
        >>> WARNINGS: PRECISION REQUIRED.
        >>> FAILURE WILL RESULT IN MISSION COMPROMISE.
        >>> GOOD LUCK, AGENT.

        >>> SEED: {SEED.decode("utf-8")}. DO NOT LOSE THIS ARTIFACT.

        [*] IMAGE AVAILABLE NOW AT: http://droppoint.pccc/

        """)
    subprocess.run(["apache2ctl", "-D", "FOREGROUND"])

if __name__ == "__main__":
    main()
