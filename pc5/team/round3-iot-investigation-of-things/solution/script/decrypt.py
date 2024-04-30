#!/usr/bin/python3

import os, sys, subprocess
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

def decrypt_data(data, key):
    cipher = AES.new(key, AES.MODE_ECB)
    encrypted_data = bytes.fromhex(data)
    decrypted_data = cipher.decrypt(encrypted_data)
    unpadded_data = unpad(decrypted_data, AES.block_size)
    return unpadded_data

def loop_keys():
    enc_str = "d99dfacb4c68f95e6b4d97e7e942f0ce"
    keys = [
    b"8fb8433941a22d52",
    b"1ff2be7b1af755da",
    b"f651913346f5eeeb",
    b"3dcf9a4307eaee9a",
    b"9995584e2654d2ee",
    b"2809e1667ce55dbb",
    b"a61f211917963980",
    b"9f64b0bd029a9bc1",
    b"d9a37eab49cf59e6",
    b"a2a921d571739b57"
    ]
    for key in keys:
        try:
            resp = decrypt_data(enc_str,key)
        except Exception as e:
            print("Incorrect Key:\t",key.decode('utf-8'))
            print("Continuing ")
        else:
            print("String Decrypted")
            print("key used:\t",key.decode('utf-8'),'\n')
            print("Decrypted String:",resp.decode('utf-8'))
            break

if __name__ == "__main__":
    loop_keys()