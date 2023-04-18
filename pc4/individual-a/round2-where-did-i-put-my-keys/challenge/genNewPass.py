#!/usr/bin/python3

# Copyright 2023 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

import os, time, datetime, random

def ord_sum(word):
    ord_val = 0
    for letter in word:
        ord_val += ord(letter)

    return ord_val

choices = []

path = r"/home/user/genNewPass.py"

date = datetime.datetime.strptime(time.ctime(os.path.getctime(path)), "%a %b %d %H:%M:%S %Y")

sort_val = int(str(date.month)+str(date.day))

words = open("/home/user/wordlist.txt", "r").read().splitlines()

words.sort(key=lambda x: abs(ord_sum(x) - sort_val))

for i in range(1, 501):
    choices.append(words[i] + words[ord(words[i][0])*(i//10)])

open("/home/user/passwd_gen", "w").write(choices[random.randrange(0,len(choices))])
