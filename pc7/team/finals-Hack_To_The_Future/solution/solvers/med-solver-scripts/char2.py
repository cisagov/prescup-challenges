# char2_padding_oracle.py
import base64
import requests

BASE = "http://safe.med.pccc:5000"
CT_URL = BASE + "/ciphertext"
DEC_URL = BASE + "/decrypt"

BLOCK_SIZE = 16

def oracle(iv_and_ct: bytes) -> bool:
    """
    True if padding is valid (200/OK), False if bad padding (403/Bad padding).
    """
    data_b64 = base64.b64encode(iv_and_ct).decode()
    r = requests.post(DEC_URL, data={"data": data_b64}, timeout=5)
    if r.status_code == 200 and "OK" in r.text:
        return True
    if r.status_code == 403 and "Bad padding" in r.text:
        return False
    return False

def decrypt_block(prev_block: bytes, cur_block: bytes) -> bytes:
    """
    Classic CBC padding-oracle attack on a single block.
    prev_block is IV (for first block) or C_{i-1}, cur_block is C_i.
    """
    assert len(prev_block) == BLOCK_SIZE
    assert len(cur_block) == BLOCK_SIZE

    recovered = bytearray(BLOCK_SIZE)     # plaintext bytes of cur_block
    intermediate = bytearray(BLOCK_SIZE)  # D_K(cur_block)

    for pad_len in range(1, BLOCK_SIZE + 1):
        pad_idx = BLOCK_SIZE - pad_len
        prefix = bytearray(BLOCK_SIZE)

        # ensure already recovered bytes produce correct padding
        for i in range(BLOCK_SIZE - 1, pad_idx, -1):
            prefix[i] = intermediate[i] ^ pad_len

        found_byte = None
        for guess in range(256):
            prefix[pad_idx] = guess
            test_prev = bytes(prefix)
            crafted = test_prev + cur_block
            if oracle(crafted):
                intermediate[pad_idx] = guess ^ pad_len
                recovered[pad_idx] = intermediate[pad_idx] ^ prev_block[pad_idx]
                found_byte = guess
                break

        if found_byte is None:
            raise RuntimeError(f"Failed to find byte for pad_len={pad_len}")

        # Show progress as each byte is recovered
        partial = recovered[pad_idx:]
        printable = "".join(chr(b) if 32 <= b < 127 else "." for b in partial)
        print(f"[*] Byte {pad_len:2d}/{BLOCK_SIZE} recovered (pos {pad_idx:2d}): {printable}")

    return bytes(recovered)

def main():
    # 1) Get IV||CT from /ciphertext
    blob_b64 = requests.get(CT_URL, timeout=5).text.strip()
    blob = base64.b64decode(blob_b64)

    blocks = [blob[i:i+BLOCK_SIZE] for i in range(0, len(blob), BLOCK_SIZE)]
    if len(blocks) < 2:
        raise SystemExit("Ciphertext too short")

    iv = blocks[0]
    c1 = blocks[1]

    print(f"[*] Fetched ciphertext: {len(blob)} bytes ({len(blocks)} blocks)")
    print(f"[*] Decrypting first block via padding oracle (up to 256 requests per byte)...")

    p1 = decrypt_block(iv, c1)
    print("[+] First plaintext block (raw):", p1)
    text = p1.decode("ascii", errors="ignore")
    print("[+] First plaintext block (ascii):", repr(text))

    marker = "char2_is:"
    i = text.find(marker)
    if i != -1 and i + len(marker) < len(text):
        char2 = text[i + len(marker)]
        print("[+] Extracted char2:", char2)
    else:
        print("[-] Could not locate 'char2_is:' marker in recovered block")

if __name__ == "__main__":
    main()

