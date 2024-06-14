#!/bin/bash

# Copyright 2024 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.


result=""

sudo -u user ssh user@shared "echo 'tartans' | sudo -S cut -d: -f1 /etc/passwd" > /home/user/users

if grep -q cshepard /home/user/users; 
    then
	result="$result GradingCheck1: Fail -- the insider's account still exists on the shared system\n"
    else
        result="$result GradingCheck1: Success -- you have removed the insider's account\n"
fi

printf "$result"
