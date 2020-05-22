#!/usr/bin/python3

import time
import os
import lorem
import random
import string
from faker import Faker
import json
from PIL import Image
from PIL import ImageFont
from PIL import ImageDraw
from stegano import lsb
import base64
from operator import itemgetter
import shutil

#define a flag for each tarball
challenge_flags = ["THEVIGENERECIPHERPROBABLYSHOULDHAVEBEENNAMEDTHEBELLASOCIPHER",
                   "THEVIGENERECIPHERISALSOKNOWNINFRENCHASLECHIFFREINDECHIFFRABLE",
                   "KASISKIFORMALIZEDTHEMETHODFORDECIPHERINGVIGENERECIPHERSINEIGHTEENSIXTYTHREE",
                   "THEVIGENERECIPHERISNAMEDAFTERBLAISEDEVIGENEREALTHOUGHBELLASOINVENTEDIT"]

#the Tyrants of Miletus - using this as index, so that players can't simply order by name and put files in correct sequence
file_keys = ["Amphitres", "Thrasybulus", "Thoas",
             "Damasanor", "Histiaeus", "Aristagoras", "Timarchus"]


def solution(current_dir):
    base_dir = current_dir + "miletus/"
    files = os.listdir(base_dir)
    
    ciphertext = ""
    for x in range(0, 20):
        for t in file_keys:
            filename = str(x) + "-" + str(t) + ".png"
            if filename in files:
                secret = lsb.reveal(base_dir + filename)
                ciphertext += secret

    print("encrypted("+current_dir+"): " + ciphertext)
    d = decrypt(ciphertext.replace("PCUPCTF{", "").replace("}", ""), key)
    print("decrypted("+current_dir+"): PCUPCTF{" + d + "}")


def decrypt(ciphertext, cipher_key):
    key_length = len(cipher_key)
    key_as_int = [ord(i) for i in cipher_key]
    ciphertext_int = [ord(i) for i in ciphertext]
    plaintext = ''
    for i in range(len(ciphertext_int)):
        value = (ciphertext_int[i] - key_as_int[i % key_length]) % 26
        plaintext += chr(value + 65)
    return plaintext


key = "PCUPCTF"
count = 0
for c in os.listdir("../output/"):
    if(c.startswith(".") or c.endswith(".zip")):
        continue
    solution("../output/" + c + "/")
