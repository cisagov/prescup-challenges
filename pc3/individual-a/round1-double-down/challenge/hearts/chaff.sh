#!/bin/env bash

# Copyright 2022 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

i=0
while [ $i -eq 0 ]
do
    nmap -A 10.5.5.0/24 > /home/user/Desktop/chaff/info.txt
    sleep 60
    nmap -p- -sP -sN 10.5.5.0/24 >> /home/user/Desktop/chaff/info.txt
    sleep 60
    wget clubs:8080
done


