#!/usr/bin/python3

# Copyright 2022 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

import random, subprocess, threading, time, base64      # takes about 10-12 seconds to complete

# file0 will always be encoded to decimal, this will decode it and print out the first line of hex code that contains the magic number (file type) -- updated and working
f0=open(f"file0", "r")
decStr=f0.readlines()
with open('f0Sol', 'w+') as f:
    decoded=''
    for line in decStr:
        line=line.strip('\n')
        if(int(line)<=9):
            decoded+=line
            continue
        if(line=='10'):
            decoded+='a'
            continue
        elif(line=='11'):
            decoded+='b'
            continue
        elif(line=='12'):
            decoded+='c'
            continue
        elif(line=='13'):
            decoded+='d'
            continue
        elif(line=='14'):
            decoded+='e'
            continue
        elif(line=='15'):
            decoded+='f'
            continue
    f.write(decoded)
subprocess.run(f"xxd -plain -revert f0Sol f0", shell=True) 

# file1 will always be encoded to unicode, this will decode it and print out the first line of hex code that contains the magic number (file type) -- uf1=open(f"file1", "r")
f1=open(f"file1", 'r')
decStr=f1.read()#.replace('\\u','')
with open('f1Sol', 'ab+') as f:
    decoded=''
    for x in range(0, len(decStr), 6):
        curUni=decStr[x:x+6].encode()
        decoded += curUni.decode('unicode-escape').encode('latin1').decode('utf-8')
    f.write(decoded.encode('unicode-escape'))
subprocess.run(f"xxd -plain -revert f1Sol f1", shell=True) 

# file2 will always be encoded to binary, this will decode it and print out the first line of hex code that contains the magic number (file type) -- updated and working
f2=open(f"file2", "r")
binStr=f2.read().replace('0b','-')
binStr+='-'
decoded=''
with open('f2Sol', 'w+') as f:
    curBin=''
    for x in binStr:
        if (x == '-'):
            if(curBin == ''):
                continue
            # either convert bin to hex, or record it somewhere with rest to convert all at once
            decoded+=str(hex(int(curBin, 2)).replace('0x',''))
            curBin=''
        else:
            curBin+=x
    f.write(decoded)
subprocess.run(f"xxd -plain -revert f2Sol f2", shell=True) 

# file3 will always be encoded to Octal, this will decode it and print out the first line of hex code that contains the magic number (file type) -- update and working
f3=open(f"file3", 'r')
octStr=f3.read().replace('0o','-')
octStr+='-'
decoded=''
with open('f3Sol', 'w+') as f:
    curOct=''
    for x in octStr:
        if (x == '-'):
            if(curOct == ''):
                continue
            hexStr=str(hex(int(curOct, 8))).replace('0x','')        # The ocatal numbers that are found to be converted are higher than your basic 1 hex character conversion. This should give insight/hint that you should be looking to convert each octal back to its 2 digit hex byte.
            if (hexStr == '0'):                        # During the conversion, leading 0's are dropped naturally by the code. So you will need to account for that and make edits to the converted hex code as needed.
                decoded+='00'
            elif (len(hexStr) == 1):
                decoded+='0'+hexStr
            else:
                decoded+=hexStr
            curOct=''
        else:
            curOct+=x
    f.write(decoded)
subprocess.run(f"xxd -plain -revert f3Sol f3", shell=True) 

# file4 will always be encoded to Base64, this will decode it and print out the first line of hex code that contains the magic number (file type)
f4=open(f"file4", 'r')
with open('f4Sol', 'w+') as f:
    b64Str=f4.read()
    chk=len(b64Str) % 4
    if (chk == 1):              # you will need to check that the b64 string is divisble by 4, if it isnt then you'll need to pad it with '=' by however much is needed to make it the correct length
        b64Str+='==='
    elif (chk == 2 ):
        b64Str+='=='
    elif (chk == 3):
        b64Str+='='
    decoded=str(base64.b64decode(b64Str).hex())
    f.write(decoded)
subprocess.run(f"xxd -plain -revert f4Sol f4", shell=True) 

# to determine each files type, youll need to analyze the hex codes file signature. The file signature or Magic Number, which is found at the beginning of the hex file Its length can vary but normally are  around 2-16 bytes. 
# They can be found with this code snippet
#magic=decoded[:15] # decoded is the hex string found after doing the correct conversion

# if its an iso, it needs to be handled a bit differently because there can be many zeros in the file before reaching anything
# that can give you the answer. So this loop goes until it hits the first non-zero number. The other trick to this is that
# the very first number in an ISO's hex code describes information on the data in the iso, so it needs to be ignored. 
# thats why this loop skips the first non-zero number and gets the magic number string after it to determine the file type.
'''
for x in range(len(decoded)):
    if (decoded[x] == '0'):
        continue
    else:
        print(decoded[x+1:x+15])
        break
'''

# After all the files code has been converted back to Hex, we will need to convert that hex code back into the actual files format using xxd in the following format
#subprocess.run(f"xxd -plain -revert *fileToBeConverted* *reverted_file.Extension*", shell=True) 

