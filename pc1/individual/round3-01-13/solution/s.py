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

import os
from fernet import Fernet
import random
import codecs
import base64
import traceback

# @@@ clases and methods
def reverse(message):
    translated = ""
    i = len(message) - 1
    while i >= 0:
        translated += message[i]
        i = i - 1
    return translated


def caesar(key, message):
    message = message.upper()
    alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    result = ""

    for letter in message:
        if letter in alpha:  # if the letter is actually a letter
            #find the corresponding ciphertext letter in the alphabet
            letter_index = (alpha.find(letter) - key) % len(alpha)

            result = result + alpha[letter_index]
        else:
            result = result + letter

    return result

def rot(text):
    enc = codecs.getencoder("rot-13")
    os = enc(text)[0]
    return os

class Affine(object):
   DIE = 128
   KEY = (7, 3, 55)

   def __init__(self):
      pass

   def encryptChar(self, char):
      K1, K2, kI = self.KEY
      return chr((K1 * ord(char) + K2) % self.DIE)

   def encrypt(self, string):
      return "".join(map(self.encryptChar, string))

   def decryptChar(self, char):
      K1, K2, KI = self.KEY
      return chr(KI * (ord(char) - K2) % self.DIE)

   def decrypt(self, string):
      return "".join(map(self.decryptChar, string))

# @@@ END clases and methods


# @@@ unencrypted messages (this is the output you should see)
msg0 = "index of first letter in the name of the smallest addressable unit of memory in most architectures"
msg1 = "index of second or fourth letter in name of oss application to view and save kerberos tickets"
msg2 = "first letter of name of famous german encryption machine in ww2 used to transmit coded messages"
msg3 = "index of first letter of digial artifact installed on server to authenticate identity of website and encrypt traffic"
msg4 = "index number of the first letter first word in name of infamous russian hacker group _ bear"
msg5 = "first letter of current united states cyber command commander last name"
msg6 = "index of _/O"
msg7 = "index of first letter unix command to modify access permissions to file system objects"
msg8 = "index of first letter unexpected event in program that disrupts the normal flow of instructions"
msg9 = "index of first letter name of current head of cia"
msg10 = "index of first letter of missing word ross ulbrect, the _ pirate roberts"
msg11 = "the same index as two and eight"
msg12 = "index of first letter of four letter application that retreives files over http https ftp and ftps"
# @@@ end unencrypted messages

s_overall = []

# @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@

with open("../challenge/0/0", "r") as f:
    s = f.readlines()[0]
# print(s[0])
s = s[::-1]
print(s)
s_overall.append("2") # bit or byte

# @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@

f = Fernet(b'LgCqSwV-aldTQzgqrF3ndMe4qG30KtTj-hUZ_PblzMI=') # from notes.txt
with open("../challenge/1/1", "r") as fi:
    s = fi.readlines()[0]
s = f.decrypt(s.encode())
print(str(s))
s_overall.append("9")  # mimikatz

# @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@

with open("../challenge/2/2", "r") as fi:
    s = fi.readlines()[0]
    s = s.strip().encode()
with open("../challenge/2/keys", "r") as fi:
    for key in fi.readlines():
        key = key.strip().encode()
        try:
            f = Fernet(key)
            s = f.decrypt(s)
            break
        except Exception as e:
            continue

print(s)
s_overall.append("5")  # enigma

# @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@

with open("../challenge/3/3", "r") as fi:
    s = fi.readlines()[0]
    s = s.strip().encode()
with open("../challenge/3/keys", "r") as fi:
    for key in fi.readlines():
        key = key.strip().encode()
        try:
            f = Fernet(key) 
            s = f.decrypt(s)
            break
        except Exception as e:
            #traceback.print_exc()
            continue

print(s)
s_overall.append("3")  # certificate

# @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@

with open("../challenge/4/4", "r") as fi:
    s = fi.readlines()[0]
    s = s.strip()
s = caesar(1, s)
print(s)
s_overall.append("6")  # fancy

# @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@

with open("../challenge/5/5", "r") as fi:
    s = fi.readlines()[0].strip()
s = caesar(2, s)
print(s)
s_overall.append("N")  # nakasone


# @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@

with open("../challenge/6/6", "r") as fi:
    s = fi.readlines()[0].strip()
s = caesar(10, s)
print(s) 
s_overall.append("9") # I/O

# @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@

with open("../challenge/7/7", "r") as fi:
    s = fi.readlines()[0].strip()
    s = rot(s)
print(s)
s_overall.append("3") # chmod

# @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@

with open("../challenge/8/8", "r") as fi:
    s = fi.readlines()[0].strip()
    s = rot(s)

print(s)
s_overall.append("5") # exception

# @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@

with open("../challenge/9/9", "r") as fi:
    s = fi.readlines()[0].strip()
    s = rot(s)

print(s)
s_overall.append("7")  # gina

# @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@

with open("../challenge/10/10", "r") as fi:
    s = fi.readlines()[0].strip()
    s = base64.b64decode(s)

print(s)
s_overall.append("4")  # dread

# @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@

affine = Affine()
with open("../challenge/11/11", "r") as fi:
    s = fi.readlines()[0].strip()
    s = affine.decrypt(s)

print(s)
s_overall.append("5")  # e

# @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@

affine = Affine()
with open("../challenge/12/12", "r") as fi:
    s = fi.readlines()[0].strip()
    s = affine.decrypt(s)
    
print(s)
s_overall.append("W")  # wget

print(s_overall)
