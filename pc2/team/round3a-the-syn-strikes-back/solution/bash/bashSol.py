#!/usr/bin/env python3

# Copyright 2022 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

#takes encrypted string and gives all the possible arguments that could of been entered that match it
#must execute this file and > output to "args.txt" file

import os, re, sys, math            # sys.argv == number of args, script name is first one
import array as arr    

en=str(sys.argv[1])
midStrs = []
dec = []
map1 = {'o': '0','l': '1','v': '2','e': '3','f': '4','w': '5','p': '6','t': '7','d': '8','q': '9'}
map2 = {'$': '0','%': '1','<': '2','&': '3','@': '4','*': '5','!': '6','?': '7','>': '8','#': '9'}
map3 = {'5': '!','3': '?','1': '#','0': '@','8': '<','2': '>','4': '$','9': '%','7': '&','6': '*'}      # finNum, this gets index from third digit of original string and converts last 

def mapper1(letter):
    for x in map1:                   # map letter back to number
        if (letter == str(x)):
            return map1[x]

def mapper2(special):
    for x in map2:                   # map special character back to number
        if (special == str(x)):
            return map2[x]

def mapper3(num):
    for x in map3:                   # map number back to special character
        if (num == str(x)):
            return map3[x]


def strMaker(index):
    for y in midStrs:
        for z in map3:
            temp = int(z) / int(y[0:1])           #gets 1st digit of current midStr
            temp = temp * int(index)
            temp = temp + int(y[1:])         #gets 2nd digit of current midStr
            finStr=str(temp)
            finNum=finStr[-1:]
            finLet=None
            for a in map1:
                if (finNum == map1[a]):
                    finLet = a
                    break
            if (finLet == en[x]):
                tempStr=str(map3[z])+str(y)
                tempStr=tempStr+str(index)
                dec.append(tempStr)

            

for x in range(len(en)):                                            #creates list of 1st and 2nd digits based off characters in string
    cur=en[x]
    converted=None
    for y in map2:
        if (y == cur):
            converted=mapper2(cur)
            midStrs.append(str(converted)+str(x))                   #this creates 1st digit and 2nd digit because they are created/converted using one another
            tempStr1=en[0:x]
            tempStr2=en[x+1:]
            en=tempStr1+"-"+tempStr2
            break


for x in range(len(en)):
        if (en[x] == "-"):
            continue
        if (en[x].isdigit() == True):
            continue
        strMaker(x)

for string in dec:
    print(string)
