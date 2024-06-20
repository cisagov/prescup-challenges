#!/bin/bash

# Copyright 2024 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.


while [ 1 ]
do
    sudo hping3 -2 -c 5 -s 1024 -d 1024 -p 11111 -E /home/user/gps-data.txt 10.3.3.97
    sleep 30
done
