#!/usr/bin/env python3

# Copyright 2022 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

import os, re, sys, math
import array as arr

file2 = open("plain.txt")

line = file2.readline().strip()
strLen = len(line)
global finStr    
lastVal=None
strs = []                           # this is a lists variable, not array
possStrs = []

square = arr.array('i', [1,4,9,16,25,36,49,64,81])

def finder():
    lastNum=0
    finStr=""
    revStrs=strs [::-1]
    found=False
    sqr=revStrs.pop(0)
    sqr=int(sqr)
    if (finStr == "" ):
        for n in square:
            n=int(n)
            if (sqr == n):
                temp=math.sqrt(n)
                temp2=math.trunc(temp)
                finStr=str(temp2)
                lastNum=int(temp2)  
    if (finStr == ""):
        return

    size=len(revStrs)
    cnt=0
    for x in range(size):
        num1=int(revStrs.pop(0))
        for odd in range(1,10,2):
            chk=lastNum+int(odd)
            if (int(chk) == int(num1)):
                finStr+=str(odd)
                lastNum=int(num1)
                cnt=cnt+1
                

    possStrs.append(finStr)       
    

def strMaker2(currStr,currVal):                            #after first run
    for x in range(1,3):            #find next number that is correct despite unknowing size/value
        if (x > len(currStr)):
            continue
        x = x * -1
        val = int(currStr[x:])     # grab each value cause match is unknown
        if (val > currVal):          # if grabbed number is greater than passed number, do next iteration
            continue
        elif (val == currVal):              # if its the same then you know its the one to continue with
            negSize=len(currStr) * -1       # get negative size of string for new subtring
            tempStr=currStr[negSize:x]  # create substring of string removing last match
            tempStr=tempStr [::-1]          # reverse string
            for y in range(1,3):
                if (y > len(tempStr)):
                    continue
                y = y * -1
                nextVal=int(tempStr[y:])
                if (nextVal > val):
                    continue
                if (int(tempStr) == nextVal):
                    strs.append(str(val))
                    strs.append(str(nextVal))
                    finder()
                    strs.pop()
                    strs.pop()
                else:
                    strs.append(str(val))
                    strMaker2(tempStr,nextVal)
                    strs.pop()

                        
def strMaker(curStr):
    for x in range(1,3):
        if (x > len(curStr)):
            continue
        x = x * -1                  #make it negative to grab last x characters of string
        val = int(curStr[x:])       #grab last x characters
        if (val > 144):
            continue
        negSize=len(curStr) * -1            #get length to know how to grab first character with negative number
        tempStr = curStr[negSize:x]    #create new substring removing last x characters, might need adjusting if it cant be the same index point with negative
        tempStr = tempStr [::-1]       #reverse it
        for y in range(1,3):
            if (y > len(tempStr)):
                    continue
            y=y*-1
            nextVal=int(tempStr[y:])
            if (nextVal > val):
                continue
            if (int(tempStr) == nextVal):
                strs.append(str(val))
                strs.append(str(nextVal))
                finder()
                strs.pop()
                strs.pop()
            else:
                strs.append(str(val))
                strMaker2(tempStr,nextVal)
                strs.pop()

            

rev=line [::-1]             # 81412
strMaker(rev)

def order(e):
    return len(e)

possStrs.sort(key=order)

for ans in possStrs:
    print(ans)
