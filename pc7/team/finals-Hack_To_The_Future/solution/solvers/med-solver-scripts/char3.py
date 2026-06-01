# char3_length_extension.py
#
# Pure-Python SHA-1 length extension against:
#   sig = sha1(MAC_SECRET + cmd_bytes)
# where the server uses:
#   cmd_bytes = cmd.encode("latin-1")

import struct
import binascii
import requests

BASE = "http://safe.med.pccc:5000"
EX_URL = BASE + "/signed_example"
SIGNED_URL = BASE + "/signed"

# -----------------------------
# Minimal SHA-1 implementation
# -----------------------------

class SHA1:
    def __init__(self, h0=None, h1=None, h2=None, h3=None, h4=None, message_byte_length=0):
        if h0 is None:
            self._h = [
                0x67452301,
                0xEFCDAB89,
                0x98BADCFE,
                0x10325476,
                0xC3D2E1F0,
            ]
        else:
            self._h = [h0, h1, h2, h3, h4]

        self._unprocessed = b""
        self._message_byte_length = message_byte_length

    def update(self, data: bytes):
        data = self._unprocessed + data
        self._message_byte_length += len(data)
        block_size = 64

        for i in range(0, len(data) // block_size * block_size, block_size):
            self._process_chunk(data[i:i + block_size])

        self._unprocessed = data[(len(data) // block_size * block_size):]

    def _left_rotate(self, n, b):
        return ((n << b) | (n >> (32 - b))) & 0xFFFFFFFF

    def _process_chunk(self, chunk: bytes):
        assert len(chunk) == 64
        w = list(struct.unpack(">16I", chunk)) + [0] * 64
        for i in range(16, 80):
            w[i] = self._left_rotate(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1)

        a, b, c, d, e = self._h

        for i in range(80):
            if 0 <= i <= 19:
                f = (b & c) | ((~b) & d)
                k = 0x5A827999
            elif 20 <= i <= 39:
                f = b ^ c ^ d
                k = 0x6ED9EBA1
            elif 40 <= i <= 59:
                f = (b & c) | (b & d) | (c & d)
                k = 0x8F1BBCDC
            else:
                f = b ^ c ^ d
                k = 0xCA62C1D6

            temp = (self._left_rotate(a, 5) + f + e + k + w[i]) & 0xFFFFFFFF
            e = d
            d = c
            c = self._left_rotate(b, 30)
            b = a
            a = temp

        self._h[0] = (self._h[0] + a) & 0xFFFFFFFF
        self._h[1] = (self._h[1] + b) & 0xFFFFFFFF
        self._h[2] = (self._h[2] + c) & 0xFFFFFFFF
        self._h[3] = (self._h[3] + d) & 0xFFFFFFFF
        self._h[4] = (self._h[4] + e) & 0xFFFFFFFF

    def digest(self) -> bytes:
        msg = self._unprocessed
        message_bit_length = self._message_byte_length * 8

        msg += b"\x80"
        msg += b"\x00" * ((56 - (len(msg) % 64)) % 64)
        msg += struct.pack(">Q", message_bit_length)

        for i in range(0, len(msg), 64):
            self._process_chunk(msg[i:i + 64])

        return struct.pack(">5I", *self._h)

    def hexdigest(self) -> str:
        return binascii.hexlify(self.digest()).decode("ascii")


def sha1_padding(message_len: int) -> bytes:
    """
    SHA-1 padding for a message of length `message_len` bytes:
    b'\\x80' + zeros + length (64-bit big-endian).
    """
    ml = message_len
    padding = b"\x80"
    pad_len = (56 - (ml + 1) % 64) % 64
    padding += b"\x00" * pad_len
    padding += struct.pack(">Q", ml * 8)
    return padding


def main():
    # 1) Get known (cmd, sig) from /signed_example
    r = requests.get(EX_URL, timeout=5)
    lines = r.text.strip().splitlines()
    cmd_line = [l for l in lines if l.startswith("cmd=")][0]
    sig_line = [l for l in lines if l.startswith("sig=")][0]

    known_cmd = cmd_line.split("=", 1)[1]
    known_sig = sig_line.split("=", 1)[1]

    print("[*] Known cmd:", known_cmd)
    print("[*] Known sig:", known_sig)

    # Treat cmd as raw bytes via latin-1 to match server
    known_cmd_bytes = known_cmd.encode("latin-1")
    suffix = b";leak_char3"

    # Initial SHA-1 state from known_sig
    h0, h1, h2, h3, h4 = struct.unpack(">5I", bytes.fromhex(known_sig))

    # Brute-force reasonable secret length range
    for secret_len in range(1, 80):
        # length of secret || known_cmd in bytes
        orig_len = secret_len + len(known_cmd_bytes)

        # Padding SHA-1 would have appended after secret||known_cmd
        pad = sha1_padding(orig_len)

        # Our extended message bytes that we want the server to hash:
        # secret || known_cmd_bytes || pad || suffix
        total_len_so_far = orig_len + len(pad)

        # Continue SHA-1 from known state, pretending we've already
        # processed `total_len_so_far` bytes.
        sha = SHA1(h0=h0, h1=h1, h2=h2, h3=h3, h4=h4,
                   message_byte_length=total_len_so_far)
        sha.update(suffix)
        new_sig = sha.hexdigest()

        # cmd parameter must be a string such that:
        #   cmd.encode("latin-1") == known_cmd_bytes + pad + suffix
        forged_bytes = known_cmd_bytes + pad + suffix
        forged_cmd = forged_bytes.decode("latin-1")

        params = {"cmd": forged_cmd, "sig": new_sig}
        resp = requests.get(SIGNED_URL, params=params, timeout=5)

        if resp.status_code == 200:
            if "char3=" in resp.text:
                print("[+] Success with secret_len =", secret_len)
                print("[+] Server response:", resp.text.strip())
                break
            else:
                # Valid MAC but no leak ΓÇô means suffix didn't parse right
                # but with latin-1 this shouldn't happen; still print for sanity.
                print(f"[?] Valid MAC but no leak, secret_len={secret_len}: {resp.text.strip()}")
    else:
        print("[-] Failed to recover char3; double-check app.py uses latin-1 in signed().")


if __name__ == "__main__":
    main()

