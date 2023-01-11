#!/usr/bin/python3

# Copyright 2023 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

def decode():
    decodedKeys = list()
    with open('encodedKeys.txt', 'r') as f:
        tmpKeys = f.read()
    encodedString = tmpKeys.replace('0o', '\n0o')
    encodedString = encodedString.replace('0x', '\n0x')
    encodedKeyList = encodedString.split('\n')
    with open('organizedEncodedKeys.txt', 'w+') as f:
        for key in encodedKeyList:
            f.write(key+'\n')
    for key in encodedKeyList:
        key = key.strip('\n')
        if key == '':
            continue
        elif key[0:2] == '0o':
            decodedKey = str(int(key, 8))
        elif key[0:2] == '0x':
            decodedKey = str(int(key, 16))

        decodedKeys.append(str(decodedKey))    
    
    with open('decodedKeys.txt','w+') as f:
        for k in decodedKeys:
            f.write(k+'\n')

if __name__=='__main__':
    decode()

