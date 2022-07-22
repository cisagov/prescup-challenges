#!/usr/bin/env python3

# Copyright 2022 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

import os, re, sys

file1 = open ("plain.txt")
file2 = open ("cipher.txt", 'w')

point = 0
ciph = ""

line = file1.readline().strip()
for x in range(0, len(line)):
    if (line[x].isalpha()):
        num = ord(line[x])
        point = point + num
        point = point % 26
        char = chr(point + 97)
        ciph += char
    elif (line[x].isdigit):
        point = point + int(line[x])
        point = point % 26
        char = chr(point + 97)
        ciph += char
    else:
        print("Invalid character entered")
        sys.exit(0)

file2.write(ciph)

file1.close()
file2.close()

