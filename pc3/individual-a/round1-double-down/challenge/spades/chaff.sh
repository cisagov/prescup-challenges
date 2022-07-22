#!/usr/env bash

# Copyright 2022 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

i=0
while [ $i -eq 0 ]
do
    arp-scan --interface=eth0 --localnet
    sleep 60
    fping -g 10.5.5.0/24    # ping sweep entire network
    sleep 60

    wget http://clubs:8080
    sleep 60
done
