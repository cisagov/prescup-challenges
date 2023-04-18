#!/bin/bash

# Copyright 2023 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

#DO NOT run script on the same directory that holds the key

#Get options and arguments
#Must provide a path to the files you wish to encrypt/decrypt and a method (encrypt/decrypt or help)

while getopts 'p:m:' option
do
    case "${option}" in
        p) path=${OPTARG};;
        m) method=${OPTARG};;
        :) "-$OPTARG requires an argument";;
    esac
done

#encrypt files - not recursive
#encrypts all files in the provided path and places the resulting files in a local directory named "encrypted"
function encrypt {
    pwd=`cat pwd`
    mkdir encrypted
    echo 'encrypting files...'
    for file in $path/*
    do
        if [ -f "$file" ]
        then
            echo 'encrypting' $file
            openssl enc -aes-256-cbc -pass pass:$pwd -p -in $file -out encrypted/${file##*/}
        fi
        echo 'All encrypted filed have been placed the in "encrypted" directory'
    done
}

#decrypt files - not recursive
#decrypts all files in the provided path and places the resulting files in a local directory named "decrypted", must use pwd file with correct
function decrypt {
    pwd=`cat pwd`
    mkdir decrypted
    echo 'decrypting files...'
    for file in $path/*
    do
        if [ -f "$file" ]
        then
            echo 'decrypting' $file
            openssl enc -aes-256-cbc -pass pass:$pwd -d -in $file -out decrypted/${file##*/}
        fi
    done
}

#Help
function help {
    echo '###Encrypting Files###'
    echo 'Example encryption: ransom -p myfiles -m encrypt'
    echo 'All files in "myfiles" will be encrypted with the key and placed in a directory named "encrypted" in the location from which the script is run'
    echo 'This process is not recursive'
    echo ''
    echo '###Decrypting Files###'
    echo 'Example decryption: ransom -p encrypted -m decrypt'
    echo 'All files in "encrypted" will be decrypted with the key and placed in a directory named "decrypted" in the location from which the script is run'
    echo 'This process is not recursive'
    echo ''
    echo 'The encryption and decryption methods are mutually exclusive'
}

if [ $method == "encrypt" ] 2> /dev/null; then
    encrypt 
elif [ $method == "decrypt" ] 2> /dev/null; then
    decrypt
elif [ $method == "-h" ] 2> /dev/null || [ $method == "help" ] 2> /dev/null; then
    help
fi
