
# Copyright 2024 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

#### NOTE CHANGE PATHS TO MATCH YOUR PC~######


with open("/home/user/challengeServer/hosted_files/unencrypted.txt", "r", encoding="utf-8") as file1:
    text1 = file1.read()

with open("/home/user/Documents/cipherkey.txt", "r", encoding="utf-8") as file2:
    text2 = file2.read()

bytes1 = text1.encode("utf-8")
bytes2 = text2.encode("utf-8")

encrypted = bytes([b1 ^ b2 for b1, b2 in zip(bytes1, bytes2)])

with open("/home/user/challengeServer/hosted_files/encrypted.txt", "wb") as output_file:
    output_file.write(encrypted)
