
# Copyright 2024 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

## read the unencrypted value
with open("./unencrypted.txt", "r", encoding="utf-8") as file1:
    text1 = file1.read()

## read the encrypted file AS BYTES

with open("./encrypted.txt", "rb",) as file2:
    encoded_value = file2.read()

## XOR The bytes against one another

original_key = bytes([b1 ^ b2 for b1, b2 in zip(encoded_value, text1.encode("utf-8"))])

### Decode the bytes as text

key_text = original_key.decode("utf-8")

## Print the original key
print(key_text)
