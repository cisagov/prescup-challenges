#!/bin/usr/python3

# Copyright 2024 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

import os, re, sys, math
import numpy as np

def inverse(det, mod):
    try:
        inverse = pow(det, -1, mod)
    except:
        print("\nDeterminant cannot be inversed which makes decryption impossible. Please select new key and try again.")
        sys.exit()
    else:
        mod_inv = inverse % mod
        return mod_inv


def minor_element(a,i,j):
    sub_a = np.delete(a,i-1,0)
    sub_a = np.delete(sub_a,j-1,1)
    minEle = np.linalg.det(sub_a)
    return np.around(minEle,decimals=3)

def cofactor_matrix(a):
    m = np.shape(a)[0]
    cofMatrix = np.zeros([m,m])
    for i in range(1,m+1):
        for j in range(1,m+1):
            cofMatrix[i-1,j-1] = pow(-1,i+j)*minor_element(a,i,j)
    return cofMatrix

def decrypt(encStr, key):
    plain = []

    numRow = len(encStr) / float(3)
    numRow = int(math.ceil(numRow))             #gets the correct num of rows to use for str matrix

    #make message matrix
    strMatrix = np.zeros([3,numRow])
    index = 0
    for x in range(numRow):                          
        for y in range(3):
            if(index < len(encStr)):
                letNum = ord(encStr[index]) % 97
                strMatrix[y,x] = letNum
                index += 1
            elif(index >= len(encStr)):
                strMatrix[y,x] = 25
                index += 1

    # make key matrix
    keyMatrix = {}
    k = 0
    for x in range(3):                           # make key matrix
        for y in range(3):
            curKey = str(x)+","+str(y)
            letNum = ord(key[k]) % 97
            keyMatrix[curKey] = letNum
            if (k < len(key) - 1):
                k += 1

    #make copy of key matrix to start the process of creating inverse key matrix
    chk = np.matrix([[keyMatrix["0,0"],keyMatrix["0,1"],keyMatrix["0,2"]], [keyMatrix["1,0"],keyMatrix["1,1"],keyMatrix["1,2"]],[keyMatrix["2,0"],keyMatrix["2,1"],keyMatrix["2,2"]]])
    d = int(round(np.linalg.det(chk),2))
    dm = inverse(d, 26)        # inverse of determinant 
    #if dm
    
    cofMatrix = cofactor_matrix(chk)
    adjMatrix = cofMatrix.transpose()
    invMatrix = np.zeros([3,3])

    for x in range(3):                  
        for y in range(3):
            if (adjMatrix[x,y] < 0):
                val = (adjMatrix[x,y] % float(26))
                adjMatrix[x,y] = val

    #Multiply by determinant inverse and mod it by 26 to get final inverse of key matrix
    for x in range(3):                  
        for y in range(3):
            val = (adjMatrix[x,y] * dm )
            val = val % 26
            invMatrix[x,y] = val
        
    # do matrix multiplication 
    dotMatrix = np.dot(invMatrix,strMatrix)
    for x in range(numRow):
        for y in range(3):
            num = dotMatrix[y,x]
            num = num % 26
            num = num + 97
            num = round(num)
            num = int(num)
            plain.append(chr(num))
    ans = "".join(plain)
    extraChars = len(encStr) % 3
    if extraChars != 0:
        ans = ans[:-extraChars]

    return ans

def encrypt(plainStr, key):
    ciph = []

    numRow = len(plainStr) / float(3)
    numRow = int(math.ceil(numRow))             #gets the correct num of rows to use for str matrix

    index = 0
    strMatrix = np.zeros([3,numRow])
    for x in range(numRow):
        for y in range(3):
            if(index < len(plainStr)):
                letNum = ord(plainStr[index]) % 97
                strMatrix[y,x] = letNum
                index += 1
            elif(index >= len(plainStr)):
                strMatrix[y,x] = 25
                index += 1

    keyMatrix = {}
    k = 0
    for x in range(3):                           # make key matrix
        for y in range(3):
            curKey = str(x)+","+str(y)
            letNum = ord(key[k]) % 97
            keyMatrix[curKey] = letNum
            if (k < len(key) - 1):
                k += 1

    # determinant = 0
    chk = np.matrix([[keyMatrix["0,0"],keyMatrix["0,1"],keyMatrix["0,2"]], [keyMatrix["1,0"],keyMatrix["1,1"],keyMatrix["1,2"]],[keyMatrix["2,0"],keyMatrix["2,1"],keyMatrix["2,2"]]])
    d = int(round(np.linalg.det(chk),2))
    # verify determinant has valid inverse
    try:
        inverse = pow(d, -1, 26)
        mod_inverse = inverse % 26
    except:
        print("\nDeterminant cannot be inversed which makes decryption impossible. Please select new key and try again.")
        sys.exit()
    
    dotMatrix = np.dot(chk,strMatrix)
    for x in range(numRow):
        for y in range(3):
            num = dotMatrix[y,x]
            num = int(num) % 26
            num = num + 97
            ciph.append(chr(num))

    ans = "".join(ciph)
    return ans

def choice(sel, input_str, key):
    input_str = input_str.strip()
    key = key.lower()
    key = key.strip()
    # Run checks to verify it passes all constraints
    if (input_str == ''):                  # check for empty string
        print("\nMessage length must be greater than 0, please try again")
        sys.exit()
    elif (any(k.isdigit() for k in key)) == True:
        print("\nNumber found in key. Key must contain letters only, please try again.")
        sys.exit()
    elif len(key) != 9:     
        print("\nIncorrect key length entered. 3x3 matrix requires 9 character key, please try again.")
        sys.exit()
    # run encryption or decryption
    if (sel == 'e'):
        plainStr = input_str
        tmpString = ''.join(c for c in plainStr if c.isalnum())
        tmpString = tmpString.lower()
        if (any(t.isdigit() for t in tmpString)) == True:
            print("\nNumber found in message. Message must contain letters only, please try again.")
            sys.exit()
        
        # check length of string submitted, if it isnt a multiple of 3, add 'z'.
        tmpStringRemainder = len(tmpString) % 3
        if tmpStringRemainder != 0:
            plainStr += 'z'*(3-tmpStringRemainder)
            tmpString += 'z'*(3-tmpStringRemainder)
            print(f"\nMessage entered not multiple of 3, Your updated string to be encrypted is:\t{plainStr}")
        encStr = encrypt(tmpString, key)
        for ind in range(len(plainStr)): 
            if plainStr[ind].isalnum() == False:
                encStr = encStr[:ind] + plainStr[ind] + encStr[ind:]
            if plainStr[ind].isupper():
                encStr = encStr[:ind] + encStr[ind:].replace(encStr[ind],encStr[ind].upper(),1)
        print(encStr)
    elif (sel == 'd'):
        encStr = input_str
        encStr = encStr.strip()
        tmpString = encStr.replace(' ','')
        key = key.lower()
        key = key.strip()
        plainStr = decrypt(tmpString, key)
        for ind in range(len(encStr)): 
            if encStr[ind] == ' ':
                plainStr = plainStr[:ind] + ' ' + plainStr[ind:]
            elif encStr[ind].isupper():
                plainStr = plainStr[:ind] + plainStr[ind:].replace(plainStr[ind],plainStr[ind].upper(),1)
        print(plainStr)

def start():
    if len(sys.argv) != 4:
        print("Script requires 3 arguments to be passed")
        print("1st is a 'e' for encryption, or a 'd' for decryption")
        print("2nd is the string you want to be encrypted/decrypted")
        print("3rd is the key to be used to encrypt/decrypt")
        sys.exit()
    sel = sys.argv[1]
    input_str = sys.argv[2]
    key = sys.argv[3]
    if (sel == 'e') or (sel == 'd'):
        choice(sel, input_str, key)
    else:
        print("First argument must be 'e' or 'd'. Please verify and try again.")
        
if __name__ == '__main__':
    start()

