#!/usr/bin/env python3

# Copyright 2022 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

import os, re, sys, math

file1 = open ("cipher.txt")
file2 = open ("plain.txt", "w+")

tot = 0
plain = ""
cnt = 0
n = 0
temp = 0

line = file1.readline().strip()
strLen = len(line)
nextNum=0

if (strLen < 2) or (strLen > 8):
    print("String must be between 2 and 8 characters")
    sys.exit(0)
for x in range(0, strLen):
    if (line[x].isdigit() == False):
        print("Encrypted string must consists of numbers only")
        sys.exit(0)
    if (int(line[x]) % 2 == 0) or (int(line[x]) == 0):
        print("Entered numbers must be odd between 1 and 9")
        sys.exit(0)
    else:
        if (x == 0):
            n = int(line[x]) * int(line[x])
            lastNum=n
        else:
            n = int(line[x]) + lastNum
            lastNum = n
    
    plain += str(n)
    plain = plain [::-1]

file2.write(plain)

file1.close()
file2.close()

