#!/bin/bash

# Copyright 2024 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

name=$(vmtoolsd --cmd "info-get guestinfo.n1") # an 8 character hex string, e.g. 12ab34cd
secret=$(vmtoolsd --cmd "info-get guestinfo.s1") # an 8 character hex string, e.g. 12ab34cd
token=$(vmtoolsd --cmd "info-get guestinfo.t1") # 1 12 character hex string, e.g. 12ab34cd56ef
dir1=$(vmtoolsd --cmd "info-get guestinfo.d1") # one of these at random; /usr/share/calendar /usr/share/color /usr/share/dict /usr/share/fonts /usr/lib/apt /usr/lib/bluetooth /usr/lib/gcc /usr/lib/grub /usr/share/bug /usr/share/alsa

echo $secret > /home/user/c03/secret/.secret.txt
echo $token > /home/user/c03/secret/.$secret.tkn
mv /home/user/c03/secret/secret.o /home/user/c03/secret/$name.o

nc -zv 10.1.1.50 22 > /dev/null

while [ $? -eq 1 ]
do
    echo "sleeping"
    sleep 5
    nc -zv 10.1.1.50 22 > /dev/null
done

scp -i /home/user/.ssh/id_rsa -O "StrictHostKeyCheck=no" /home/user/c03/secret/.secret.txt user@10.1.1.50:/home/user/
scp -i /home/user/.ssh/id_rsa -O "StrictHostKeyCheck=no" /home/user/c03/secret/.*.tkn user@10.1.1.50:/home/user/
scp -i /home/user/.ssh/id_rsa -O "StrictHostKeyCheck=no" /home/user/c03/secret/$name.o user@10.1.1.50:/home/user/
ssh user@10.1.1.50 "echo 'tartans' | sudo -S mv /home/user/.*.tkn /usr/local/games/"
ssh user@10.1.1.50 "echo 'tartans' | sudo -S mv /home/user/.secret.txt /usr/local/games/"
ssh user@10.1.1.50 "echo 'tartans' | sudo -S mv /home/user/$name.o $dir1/"
ssh user@10.1.1.50 "echo 'tartans' | sudo -S touch -a -m -r /usr/share/calendar/calendar.argentina /usr/local/games/*
