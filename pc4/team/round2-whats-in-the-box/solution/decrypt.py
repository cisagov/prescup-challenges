#!/usr/bin/python3 

# Copyright 2023 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

import subprocess, sys, math, json

def checkNonChar(cipher):
    index = 0
    nonChar = ['.', ':',' ']
    nonCharMapping = []
    while index < len(cipher):
        if cipher[index] in nonChar:
            nonCharMapping.append([index, cipher[index]])            
        index += 1
    return nonCharMapping

def decrypt():
    cipher = ''         # enter cipher string here
    cipherOrg = ''      # enter cipher string here
    key = ''            # enter key here (username created)

    cipher = cipher.replace(' ','')
    cipher = cipher.replace('.','')
    cipher = cipher.replace(':','')
    columns = math.ceil(len(cipher)/len(key))
    rows = len(key)

    numExtraBoxes = (columns * rows) - len(cipher)
    lettersToInsertExtraBox = ''
    if numExtraBoxes > 0:
        tmpIndex = numExtraBoxes * (-1)
        lettersToInsertExtraBox = key[tmpIndex:]

    mapper = dict()
    cipherList = list(cipher)
    decrypted = ''
    for k in sorted(key):
        x = 0
        while x < columns:
            if (x == (columns -1)) and (k in lettersToInsertExtraBox):
                decrypted += ' '
                x += 1
                continue
            try: 
                decrypted += cipherList.pop(0)
                x += 1
            except IndexError:
                continue
        mapper[k] = decrypted
        decrypted = ''

    newMap = dict()
    for k in key:
        #print(k,' : ', mapper[k])
        newMap[k] = list(mapper[k])
    
    plainText = ''
    for x in range(columns):
        for k in key:
            try: plainText += newMap[k].pop(0)
            except IndexError: 
                print(k)
                continue
    
    nonCharMap = checkNonChar(cipherOrg)
    
    for entry in nonCharMap:
        plainText = plainText[:entry[0]]+entry[1]+plainText[entry[0]:]

    print(plainText)


if __name__ == '__main__':
    decrypt()
