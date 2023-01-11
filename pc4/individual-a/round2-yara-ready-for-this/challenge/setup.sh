#!/bin/bash

# Copyright 2023 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

registrytoken="a1b2c3d4a1b2c3d4"
# encrypt the token and write it to a file
dotnet ./setup/EncryptString/EncryptString.dll jHrtUd0weG43qas9 $registrytoken
# copy ouput value to text file
cp ./setup/EncryptString/output.txt ./malicious-web-server/reg/registrytoken.txt

# create file with encryptedfiletoken
encryptedfiletoken="aaaa1111bbbb2222"
echo "You located the encrypted file token: $encryptedfiletoken" > ./setup/personal.txt
dotnet ./setup/EncryptFileContents/EncryptFileContents.dll -e ./setup/personal.txt $registrytoken
cp ./setup/personal.txt.encrypted ./malicious-web-server/xkBr34mn0/personal.txt.encrypted

# get random number to append to SAM file names and encrypt it for download
samtoken=5150
dotnet ./setup/EncryptString/EncryptString.dll jHrtUd0weG43qas9 $samtoken
cp ./setup/EncryptString/output.txt ./malicious-web-server/reg/samtoken.txt

# get random port and encrypt it for download
randomport=4150
dotnet ./setup/EncryptString/EncryptString.dll jHrtUd0weG43qas9 $randomport
cp ./setup/EncryptString/output.txt ./malicious-web-server/reg/randomport.txt

hiddenfiletoken="1a1a1a1a"
dotnet ./setup/EncryptString/EncryptString.dll jHrtUd0weG43qas9 $hiddenfiletoken
cp ./setup/EncryptString/output.txt ./malicious-web-server/c34gUh65rb/hiddenfiletoken.txt

memorytoken="2b2b2b2b"
dotnet ./setup/EncryptString/EncryptString.dll jHrtUd0weG43qas9 $memorytoken
cp ./setup/EncryptString/output.txt ./malicious-web-server/j3edcrop99/memorytoken.txt

# log that the startup script is done and was successful
echo "Done with startup configuration. Success."
