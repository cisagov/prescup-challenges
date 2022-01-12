
# Copyright 2022 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

import sys

def decode(s):
    d = 5437
    n = 71243  
    return (s**d) % n

with open("./challenge/problem 3/encrypted-1.txt", "r") as fp:
    encoded = fp.read()
    text = encoded.split(", ")
    decoded = ""
    for ch in text:
        decoded += chr(decode(int(ch)))
    print(decoded)

