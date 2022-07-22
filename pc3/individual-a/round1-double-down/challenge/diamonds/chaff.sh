#!/bin/env bash

# Copyright 2022 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

i=0
while [ $i -eq 0 ]
do
    # convo
    sudo hping3 -c 1 -n spades  -e "Hey Bob, Just wanted to give a heads up that I've finished the Q1 numbers and sending it Homers FTP share"
    sleep 30
    # transfer spreadsheet to clubs
    /usr/bin/expect << EOF
        spawn ftp clubs
        expect "ftp>"
        send "cd uploads\r"
        expect "ftp>"
        send "put /home/user/Desktop/chaff/Q1.ods /uploads/Q1.ods\r"
        expect "ftp>"
        send "exit\r"
        expect eof
EOF

    sleep 30
    wget http://clubs:8080
done
