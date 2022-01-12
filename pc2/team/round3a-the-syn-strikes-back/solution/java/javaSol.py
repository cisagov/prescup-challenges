#!/usr/bin/env python3

# Copyright 2022 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

import os, re, sys, math            # sys.argv == number of args, script name is first one
import array as arr                 # sys.argv[#] gets specific one, again script is first one [0]

en=str(sys.argv[1])
mapping = {'0': 'g','1': 'q','2': 'b','3': 'j','4': 'n','5': 'u','6': 'c','7': 'h','8': 'z','9': 'l','10': 'd','11': 't','12': 'k','13': 'p',
           '14': 'v', '15': 'e', '16': 's', '17': 'i','18': 'y','19': 'w','20': 'm','21': 'f','22': 'o','23': 'a','24': 'r','25': 'x'}    

def mapper(letter):
    for x in mapping:                   # map the letter back to value
        if (letter == str(mapping[x])):
            return x

def pairFinder(num):
    pairs=[]
    for x in range(97,123):
        for y in range(97,123):
            z = x + y
            if (num == z):
                pairs.append(str(x)+","+str(y))
    return pairs

def strMaker(start, curVal):
    global plain
    currStr=str(en[start:start+4])
    nextLet=str(currStr[-1:])
    nextNumLet=mapper(nextLet)
    num=int(currStr[0:3])
    pairs2 = pairFinder(num)
    for x in pairs2:
        index=x.find(",")
        nextNum1 = int(x[:index])
        nextNum2 = int(x[index+1:])
        next1 = mapper(chr(nextNum1))                          # checks if this was number in original string
        next2 = mapper(chr(nextNum2))
        next3 = int(next1)+int(next2)+int(curVal)               #previous numbers added + new numbers found i.e: 3+4 + 3
        temp=next3

        if (next3 > 25):
            temp = temp % 26

        if (str(temp) == str(nextNumLet)):
            nextVal=next3
            tempStr=plain
            plain = str(plain)+str(next1)+str(next2)
            index=start+4
            if (index >= len(en)):
                print(plain)                        # prints all possible strings that fit criteria
                plain=tempStr
            else:
                strMaker(index, nextVal)
                plain=tempStr
           

curStr=str(en[0:4])
let=str(curStr[-1:])
numLet = mapper(let)                    # c here
num=int(curStr[0:3])
pairs = pairFinder(num)
for y in pairs:
    index=y.find(",")
    num1 = int(y[:index])
    num2 = int(y[index+1:])
    n1 = mapper(chr(num1))
    n2 = mapper(chr(num2))
    n3 = int(n1) + int(n2)

    if(str(numLet) == str(n3)):
        plain = str(n1)+str(n2)
        index=4
        strMaker(index, n3)    


