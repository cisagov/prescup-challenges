#!/bin/env bash

# Copyright 2022 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

#remIp=`host spades | tail -c 11 | tr -d \\n`        # get IP of spades if needed
fileName='four'
aesKey='24bc87abcca700c0'
fileContent='sick advise soar cut brake'


# create RSA key to 
/usr/bin/expect <<- DONE
    spawn -noecho ssh-keygen -t rsa
    expect "*id_rsa*"
    send -- "\n"
    expect "*passphrase*"
    send -- "\n"
    expect "*passphrase*"
    send -- "\n"
    expect eof
DONE

/usr/bin/expect <<- DONE        # should transfer key to spades, if it doesnt then just pre-load it & save
    set timeout -1
    spawn -noecho /bin/bash -c -- "cat /home/user/.ssh/id_rsa.pub | ssh user@spades 'cat >> .ssh/authorized_keys'"
    expect "*password*"
    send -- "Fu11H0us3\n"
    expect "eof"
DONE


# Create file with specified content and use GPG to encrypt file via AES
echo $fileContent > /home/user/Desktop/setup/$fileName
newFile="$fileName.gpg"
gpg --pinentry-mode loopback --output /home/user/Desktop/setup/$newFile --symmetric --passphrase $aesKey /home/user/Desktop/setup/$fileName

# Get AES key and cut it up into 4 parts, each containing 4 characters
a1=${aesKey:0:4}
a2=${aesKey:4:4}
a3=${aesKey:8:4}
a4=${aesKey:12:4}

# loop conversation, hpings, SSH key transfer, file transfer, and AES key transfer
i=0
while [ $i -eq 0 ]
do
    sudo hping3 -c 1 -n spades -d 100 -e "like we discussed, SSH key incoming..." -1
    sleep 5
    sudo hping3 -c 1 -n spades -d 570 -E /home/user/.ssh/id_rsa.pub -1       # sends SSH key for spades to extract and configure his machine with
    sleep 20
    scp /home/user/Desktop/setup/$newFile user@spades:/home/user/Desktop         # transfer encrypted file via scp
    sleep 30

    sudo hping3 -c 1 -n spades -d 100 -e "now ill be sending the aes key, hope you remember how to receive it" -1
    sleep 5
    sudo hping3 -c 1 -n spades -d 70 -e "$a1" -1       # Send 1st part of AES key
    sleep 10
    sudo hping3 -c 1 -n spades -d 70 -e "$a2" -1       # Send 2nt part of AES key
    sleep 15
    sudo hping3 -c 1 -n spades -d 70 -e "$a3" -1       # Send 3rd part of AES key
    sleep 20
    sudo hping3 -c 1 -n spades -d 70 -e "$a4" -1       # Send 4th part of AES key
    sleep 25
done
