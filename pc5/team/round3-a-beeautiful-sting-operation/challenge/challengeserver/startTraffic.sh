#!/bin/bash

# Copyright 2024 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

dir="/home/user/c57"

sleep 60
status_ssh=1
while [ $status_ssh -eq 1 ]
do
    echo "sleeping"
    sleep 5
    nc -zv 10.7.7.200 22 > /dev/null
    status_ssh=$?
done

# SCP target file for task 2
file2=`vmtoolsd --cmd "info-get guestinfo.f2"` # an integer between 1 and 5
$dir/p2/scp$file2.sh

# Send emails based on locations picked by transform for task 3
status_mail=1
while [ $status_mail -eq 1 ]
do
    echo "sleeping"
    sleep 5
    nc -zv 10.7.7.200 25 > /dev/null
    status_mail=$?
done

loc1=`vmtoolsd --cmd "info-get guestinfo.index"` # an integer between 1 and 5
loc2=$(( (loc1 + 3) % 5 ))
if [ "$loc2" -eq 0 ]; then loc2=5; fi
$dir/p3/swaks$loc1.sh
$dir/p3/swaks$loc2.sh
