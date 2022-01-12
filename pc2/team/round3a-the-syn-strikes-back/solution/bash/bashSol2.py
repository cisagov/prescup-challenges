#!/usr/bin/env python3

# Copyright 2022 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

#uses file made in first script, and reads it in and creates all possible permutations of 5 arguments that could of been entered off of original string and writes it to file

import os, re, sys, math            
import array as arr    
import itertools
from itertools import permutations
import subprocess
from subprocess import Popen, PIPE

arg = []

with open("args.txt") as file1:
    lines = file1.readlines()
for line in lines:
    line=line.strip()
    arg.append(line)

def findsubsets(s,n):
    for x in itertools.permutations(s,n):
        global passed
        indexs = []
        temp=str(x)
        temp=temp.strip()
        temp=temp.replace('(','')
        temp=temp.replace(')','')
        temp=temp.replace(',','')
        temp=temp.replace('\'','')
        for y in range(0,len(temp),5):
            curStr=temp[y:y+4]
            #print(curStr)
            index1=curStr[2]
            index2=curStr[3]
            chk1 = index1 in indexs
            chk2 = index2 in indexs
            if ((chk1 == True) or (chk2 == True)):
                passed=False
                break
            if (chk1 == False):
                indexs.append(index1)
            if (chk2 == False):
                indexs.append(index2)
            if (len(indexs) == 10):
                passed=True
        if (passed==True):
            print(temp)

s = arg
n = 5

findsubsets(s,n)


