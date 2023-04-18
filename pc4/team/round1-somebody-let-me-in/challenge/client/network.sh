#!/bin/bash

# Copyright 2023 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

#This script will apply random IP addresses to the system within the required subnets using virtual adapters.
ip1=$(($RANDOM%240+10))
echo "FOB 1's IP will be 133.45.151."$ip1
ip2=$(($RANDOM%240+10))
echo "FOB 2's IP will be 133.45.152."$ip2

#for non-Ubuntu Linux variants, you can use the following scripts to apply the network settings. Substitute adapter names or OS variant specific syntax as needed.
sudo ifconfig eth0:0 133.45.151.$ip1 netmask 255.255.255.0
sudo ifconfig eth0:1 133.45.152.$ip2 netmask 255.255.255.0


