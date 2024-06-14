#!/bin/bash

# Copyright 2024 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

result=""

#Grading check
 
if [ $(nmap -Pn 10.10.10.100 -p 80 | grep open | wc -l) = 1 ]
    then 
        if [ $(nmap -Pn 10.10.10.100 -p 1337 | grep open | wc -l) = 0 ]
            then
                result="$result GradingCheck1: success -- port 1337 is blocked to IP 10.10.10.100\n"
        else
            result="$result GradingCheck1: fail -- port 1337 is still open to IP 10.10.10.100\n"
        fi
    else
        result="$result GradingCheck1: fail -- required traffic is blocked to 10.10.10.100\n"
fi
                           
printf "$result"
