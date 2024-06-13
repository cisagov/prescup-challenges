#!/bin/bash

# Copyright 2024 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.


sleep 75

octet1=`vmtoolsd --cmd 'info-get guestinfo.o1' | cut -d ' ' -f1`
octet2=`vmtoolsd --cmd 'info-get guestinfo.o2' | cut -d ' ' -f1`
octet3=`vmtoolsd --cmd 'info-get guestinfo.o3' | cut -d ' ' -f1`
octet4=`vmtoolsd --cmd 'info-get guestinfo.o4' | cut -d ' ' -f5`
ip="$octet1.$octet2.$octet3.$octet4"

sed -i "s/##o1##.##o2##.##o3##.##o4##/$ip/g" /etc/netplan/01-network-manager-all.yaml
netplan apply

token2=`vmtoolsd --cmd 'info-get guestinfo.token2'`

mysql -u user --password=password -e "UPDATE tokens.tokens SET tokentwo = '$token2';"
