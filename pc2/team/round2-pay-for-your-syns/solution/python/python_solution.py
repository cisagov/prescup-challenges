#!/usr/bin/env python3

# Copyright 2022 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

import os, re, sys

def checkerVal(val):
    if val < 10:
        return str(val)
    else:
        return chr(val)

def decrypt(currStr, enString, pos, point):
    global i
    for x in range(pos, len(enString)):
        val = ord(enString[x])
        v = val - 97 - point

        while v < 0:            #if negitive
            v += 26

        if v < 10:              #if it is a number
            num = int(v)
            npoint = point + num
            newCurStr = currStr + checkerVal(v)
            decrypt(newCurStr,enString,x+1, npoint)

            while v < 97:
                v+=26
        if v > 10:
            while v <= 122:
                if (v <= 122 and v >= 97):
                    npoint = point + v
                    newCurStr = currStr + checkerVal(v)
                    decrypt(newCurStr, line, x+1, npoint)
                v += 26
    
    
    if len(currStr) == len(enString):
        with open("decString{}.txt".format(i),"w") as f:
            f.write("{}".format(currStr))
            i=i+1

file2 = open("cipher.txt")
point = 0
result = []

i=0
line = file2.readline().strip()
decrypt("",line, 0, 0)

