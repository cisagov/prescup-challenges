
# Copyright 2022 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

import subprocess
import os
import json

from Crypto.Util.Padding import pad
from Crypto.Cipher import AES
from flask import Flask

app = Flask(__name__)

XOR_KEYS = [
    b'K\x8c\x0btSX\xfc\xe03:F\x9e\x19\xa1`\x9d',
    b'\xa17\xe5t\x08r\xe3W\xe4]\xc3z)m`\xc1',
    b'v\xc0\xbd\xd5O\x14\x91ip"u\x7f\xbe\x1b\x05\x89',
    b't\x1a\rF\xd2!\x9e\xdd\xdc\xcaj\x086.\x96P',
    b'S\xea\xb6G\xbc\x97\xa3\x85\x1e\x9d,\xe9\x9d\x83\xb4P',
    b'W\x02o\x8b\xef\xa9\xfdb\x16\x1e\xb2N&\x16\x9b\x7f',
    b' s\x0e\xb3\xf2\xa5\x08\x9b\x05\xed\xf4(\xf96\xa9\x03',
    b'\\\x1d\xd0\xe2\xd9\xf0%\x7faAVU\x8c\xb9"\xce'
]
AES_KEYS = [
    b'\x97R\xfe{i\x80\x9a\xeb(h\xb1]\x99\xcd\xce$',
    b'\xb7Z\x9f\x18\xf7\t\x84 \xc6}o\x07\xa2\xdf\xc6\x86',
    b'L\xbd\xb3u\xaa\xb2\xc5\x86\x947-z-b\x93}',
    b'\xd6(B\x81\xfc\xaf\xe1\xef\xc5\xb9u2\xa2\x94\xab\x0b',
    b'\x8b\x95\xb5x\xde\xc0*\x11\xdf\\:\xfeRi\xbf}',
    b'\xa6\xdf\x1aA\xf91\xd6\xc5\x0cIM"\x1bYks',
    b'L\xbf\n\xf8\x0eu,\x08\x14\xddk\xe0;$}\x9a',
    b'W(1\x99\xb7sV>`\xfb\xae\xb7\x11\xf7Q\xb1'
]


def xor_encrypt(plaintext: bytes, key: bytes) -> bytes:
    """ Encrypts plaintext with the given key. Requires that len(plaintext) == len(key).

    :param plaintext: A bytes representation of some plaintext.
    :param key: A key whose length should equal the given plaintext length.
    :returns: The encrypted plaintext.
    :raises ValueError: If the plaintext and key lengths differ.
    """
    # Changed for open sourcing
    #if len(plaintext) != len(key):
    if len(plaintext) > len(key):
        raise ValueError("plaintext and key size differ.")
    # New
    elif len(plaintext) < len(key):
        # Pad the plaintext
        diff = len(key) - len(plaintext)
        plaintext += b"\0" * diff
    return bytes((x ^ y for x, y in zip(plaintext, key)))


def aes128cbc_encrypt(plaintext: bytes, key: bytes) -> bytes:
    """ Encrypts plaintext with the given key.

    :param plaintext: A bytes representation of some plaintext.
    :param key: A key whose length should be 16 bytes.
    :returns: The encrypted plaintext, prefixed by the 16-byte iv.
    :raises ValueError: If the key length is not 16.
    """
    if len(key) != 16:
        raise ValueError("key size is not 16 bytes.")
    cipher = AES.new(key, AES.MODE_CBC)
    return cipher.iv + cipher.encrypt(pad(plaintext, 16))


def get_guestinfo(var_name: str) -> str:
    """ Requires vmtoolsd to be installed. Fetches a guestinfo variable
    of the form `guestinfo.{var_name}`.
    """
    # Added for open sourcing
    return b"Success!"
    # Original code
    result = subprocess.run(
        ["vmtoolsd", "--cmd", f"info-get guestinfo.{var_name}"],
        capture_output=True)
    return result.stdout.strip()


@app.route("/flag1")
def flag1():
    current = get_guestinfo("flag1")
    for key in XOR_KEYS:
        current = xor_encrypt(current, key)
    return current


@app.route("/flag2")
def flag2():
    current = get_guestinfo("flag2")
    for key in AES_KEYS:
        current = aes128cbc_encrypt(current, key)
    return current


@app.route("/flag3")
def flag3():
    return get_guestinfo("flag3")


if __name__ == "__main__":
    # Changed for open sourcing
    #app.run(host="0.0.0.0")
    app.run(port=8000)

