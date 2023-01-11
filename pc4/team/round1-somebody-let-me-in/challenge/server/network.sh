#!/bin/bash

# Copyright 2023 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

#This script will apply the necessary server/receiver IP addresses to the system within the required subnets using virtual adapters.

#for non-Ubuntu Linux variants, you can use the following scripts to apply the network settings. Substitute adapter names or OS variant specific syntax as needed.
sudo ifconfig eth0:2 133.45.151.250 netmask 255.255.255.0
sudo ifconfig eth0:3 133.45.152.250 netmask 255.255.255.0
sudo ifconfig eth0:4 133.45.153.250 netmask 255.255.255.0
