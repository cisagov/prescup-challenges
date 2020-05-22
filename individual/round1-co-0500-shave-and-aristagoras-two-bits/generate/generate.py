#!/usr/bin/python3

"""
President's Cup Cybersecurity Competition 2019 Challenges

Copyright 2020 Carnegie Mellon University.

NO WARRANTY. THIS CARNEGIE MELLON UNIVERSITY AND SOFTWARE ENGINEERING
INSTITUTE MATERIAL IS FURNISHED ON AN "AS-IS" BASIS. CARNEGIE MELLON
UNIVERSITY MAKES NO WARRANTIES OF ANY KIND, EITHER EXPRESSED OR
IMPLIED, AS TO ANY MATTER INCLUDING, BUT NOT LIMITED TO, WARRANTY OF
FITNESS FOR PURPOSE OR MERCHANTABILITY, EXCLUSIVITY, OR RESULTS
OBTAINED FROM USE OF THE MATERIAL. CARNEGIE MELLON UNIVERSITY DOES NOT
MAKE ANY WARRANTY OF ANY KIND WITH RESPECT TO FREEDOM FROM PATENT,
TRADEMARK, OR COPYRIGHT INFRINGEMENT.

Released under a MIT (SEI)-style license, please see license.txt or
contact permission@sei.cmu.edu for full terms.

[DISTRIBUTION STATEMENT A] This material has been approved for public
release and unlimited distribution.  Please see Copyright notice for
non-US Government use and distribution.

DM20-0347
"""

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

#we'll make random tarballs
challenge_tarballs = ["first", "second", "third", "fourth"]
#define a flag for each tarball
challenge_flags = ["THEVIGENERECIPHERPROBABLYSHOULDHAVEBEENNAMEDTHEBELLASOCIPHER",
                   "THEVIGENERECIPHERISALSOKNOWNINFRENCHASLECHIFFREINDECHIFFRABLE",
                   "KASISKIFORMALIZEDTHEMETHODFORDECIPHERINGVIGENERECIPHERSINEIGHTEENSIXTYTHREE",
                   "THEVIGENERECIPHERISNAMEDAFTERBLAISEDEVIGENEREALTHOUGHBELLASOINVENTEDIT"]

#the Tyrants of Miletus - using this as index, so that players can't simply order by name and put files in correct sequence
file_keys = ["Amphitres", "Thrasybulus", "Thoas", "Damasanor", "Histiaeus", "Aristagoras", "Timarchus"]

def randomString(stringLength=10):
    """Generate a random string of fixed length """
    letters = string.ascii_lowercase
    return ''.join(random.choice(letters) for i in range(stringLength))

def generate_profiles():
    """generate people profiles using faker, so that it looks like stolen identities"""
    print("generating profiles for "+ current_dir +"...")
    with open('names.txt') as fp:
        for cnt, line in enumerate(fp):
            line = line.strip()
            dir = current_dir + "profiles/" + line[0] + "/"
            if not os.path.exists(dir):
                os.makedirs(dir)
            dir += line + "/"
            if not os.path.exists(dir):
                os.makedirs(dir)
            else:
                continue
            
            chance = random.randint(0, 1)
            if chance > 0:
                continue
            
            file = open(dir + lorem.sentence().replace(".", "") + ".txt", "w")
            file.write(lorem.text())
            file.close()

            for i in range(random.randint(0, 22)):
                with open(dir + "/%s-%s.bin" % (time.time(), i), "wb") as fout:
                    fout.write(os.urandom(random.randint(1, 2048)))
                    fout.close()


def generate_logs(folder):
    print("generating logs for " + current_dir + "...")
    for count in range(100):
        line = randomString()
        dir = current_dir + folder + "/"
        if not os.path.exists(dir):
            os.makedirs(dir)
        dir += line + "/"
        if not os.path.exists(dir):
            os.makedirs(dir)
        else:
            continue

        chance = random.randint(0, 1)
        if chance > 0:
            continue

        for i in range(random.randint(0, 22)):
            with open(dir + "%s-%s.log" % (time.time(), i), "wb") as fout:
                fout.write(os.urandom(random.randint(1, 2048)))
                fout.close()


def generate_pii(folder, rng):
    print("generating pii for " + current_dir + "...")
    base_dir = current_dir + folder + "/"
    if not os.path.exists(base_dir):
        os.makedirs(base_dir)

    for count in range(rng):
        faker = Faker()
        line = faker.profile()
        dir = base_dir + line["username"][0] + "/"
        if not os.path.exists(dir):
            os.makedirs(dir)
        
        with open(dir + "%s-%s-%s.json" % (line["username"], time.time(), count), "w") as fout:
            fout.write(str(line))
            fout.close()
            
def generate_images(dir_name, word):
    print("generating images for " + current_dir + " " + dir_name + "...")
    clear_message = ""
    current_index = 0
    loop_index = 0
    print("generating word: " + word)
    for count in range(len(word)):
        base_dir = current_dir + dir_name + "/"
        if not os.path.exists(base_dir):
            os.makedirs(base_dir)

        current = word[count]

        file = base_dir + str(loop_index) + "-" + file_keys[current_index] + '.png'
        height = random.randint(50, 955)
        width = random.randint(250, 955)
        img = Image.new('RGB', (width, height))
        
        draw = ImageDraw.Draw(img)
        fonts_path = "~/Library/Fonts"
        font = ImageFont.truetype(os.path.join(fonts_path, 'slkscr.ttf'), 9)
        draw.text((0, random.randint(10, height-20)), randomString(random.randint(2, 255)),
                  (random.randint(50, 255), random.randint(50, 255), random.randint(50, 255)), font=font)
        img.save(file)
        secret = lsb.hide(file, current)
        secret.save(file)
        clear_message += lsb.reveal(file)
        current_index = current_index + 1
        if current_index > 6:
            current_index = 0
            loop_index = loop_index + 1


def plain_image(dir_name, rng):
    print("generating plain images for " + current_dir + " " + dir_name + "...")
    base_dir = current_dir + dir_name + "/"
    if not os.path.exists(base_dir):
        os.makedirs(base_dir)

    for _ in range(rng):
        file = base_dir + randomString(10) + '.png'
        height = random.randint(50, 355)
        width = random.randint(150, 255)
        img = Image.new('RGB', (width, height))
        draw = ImageDraw.Draw(img)
        fonts_path = "~/Library/Fonts"
        font = ImageFont.truetype(os.path.join(fonts_path, 'slkscr.ttf'), 9)
        draw.text((0, random.randint(10, height-20)), randomString(10),
                  (random.randint(50, 255), random.randint(50, 255), random.randint(50, 255)), font=font)
        img.save(file)

def generate_folders():
    base_dir = current_dir
    if not os.path.exists(base_dir):
        os.makedirs(base_dir)
    folders = ["_persia","abscissa","conf","dat","drivers","gat","incomplete","ionia","kryp0s","larssons","logs",
        "miletus","orbs","palimpsest","presia","profiles","raw","tis","transposition","txt","var"]
    for folder in folders:
        dir = base_dir + folder + "/"
        if not os.path.exists(dir):
            os.makedirs(dir)

def false_flag(path, file, flag_text):
    base_dir = current_dir + path + "/"
    if not os.path.exists(base_dir):
        os.makedirs(base_dir)

    with open(base_dir + file, "w") as fout:
        content = str(flag_text)
        fout.write(content)
        fout.close()


def base_64_it(path, file, text):
    print("generating base64 for "+ current_dir +"...")
    base_dir = current_dir + path + "/"
    if not os.path.exists(base_dir):
        os.makedirs(base_dir)

    with open(base_dir + file, "w") as fout:
        content = str(base64.b64encode(bytes(str(text), 'utf-8')))
        fout.write(content)
        fout.close()


def encrypt(plaintext, key):
    key_length = len(key)
    key_as_int = [ord(i) for i in key]
    plaintext_int = [ord(i) for i in plaintext]
    ciphertext = ''
    for i in range(len(plaintext_int)):
        value = (plaintext_int[i] + key_as_int[i % key_length]) % 26
        ciphertext += chr(value + 65)
    return ciphertext


def decrypt(ciphertext, cipher_key):
    key_length = len(cipher_key)
    key_as_int = [ord(i) for i in cipher_key]
    ciphertext_int = [ord(i) for i in ciphertext]
    plaintext = ''
    for i in range(len(ciphertext_int)):
        value = (ciphertext_int[i] - key_as_int[i % key_length]) % 26
        plaintext += chr(value + 65)
    return plaintext

def solution():
    base_dir = current_dir + "miletus/"
    files = os.listdir(base_dir)
    
    ciphertext = ""
    for x in range(0,20):
        for t in file_keys:
            filename = str(x) + "-" + str(t) + ".png"
            if filename in files:
                secret = lsb.reveal(base_dir + filename)
                ciphertext += secret

    print("encrypted("+current_dir+"): " + ciphertext)
    d = decrypt(ciphertext.replace("PCUPCTF{", "").replace("}", ""), key)
    print("decrypted("+current_dir+"): PCUPCTF{" + d + "}")


def copy_directory(src, dest):
    src_files = os.listdir(src)
    for file_name in src_files:
        full_file_name = os.path.join(src, file_name)
        if os.path.isfile(full_file_name):
            shutil.copy(full_file_name, dest)


print("running...")
print("")

count = 0
for c in challenge_tarballs:
    current_dir = "../" + c + "/"
    
    # generate_folders()
    # generate_profiles()
    # generate_logs("logs")
    # generate_pii("larssons", 2333)
    # generate_pii("krypt0s", 2001)
    # generate_pii("palimpsest", 102)
    # generate_pii("abscissa", 2)
    # generate_pii("transposition", 3)
    # plain_image("presia", 12)
    # plain_image("profiles", 112)

    # for _ in range(59):
    #     base_64_it("var", randomString(10) + ".txt", randomString(10000))
    # false_flag("var", randomString(10) + ".txt", randomString(1000) + "pcupCTF{nice_try_but_not_a_flag}" + randomString(1000))

    # ## copy _presia dat gat orbs raw tis
    # copy_directory("_persia", current_dir + "_persia")
    # copy_directory("dat", current_dir + "dat")
    # copy_directory("gat", current_dir + "gat")
    # copy_directory("orbs", current_dir + "orbs")
    # copy_directory("raw", current_dir + "raw")
    # copy_directory("tis", current_dir + "tis")

    flag = challenge_flags[count]
    key = "PCUPCTF"
    cipher_flag = encrypt(flag, key)
    print(cipher_flag)
    decrypted = decrypt(cipher_flag, key)
    print(decrypted)

    # generate_images("miletus", "PCUPCTF{" + cipher_flag + "}")
    # # shutil.copy("key.py", current_dir + "miletus/key.py")

    solution()
    count = count + 1

print("")
print("")
print("")
print("Finis!")
