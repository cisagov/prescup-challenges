#!/bin/bash

# Copyright 2024 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.


sleep 60

token1=`vmtoolsd --cmd 'info-get guestinfo.token1'`
echo $token1 > /home/user/token1.txt
chown user /home/user/token1.txt

octet1=`vmtoolsd --cmd 'info-get guestinfo.o1' | cut -d ' ' -f2`
octet2=`vmtoolsd --cmd 'info-get guestinfo.o2' | cut -d ' ' -f2`
octet3=`vmtoolsd --cmd 'info-get guestinfo.o3' | cut -d ' ' -f2`
octet4=`vmtoolsd --cmd 'info-get guestinfo.o4' | cut -d ' ' -f6`
ip="$octet1.$octet2.$octet3.$octet4"


sed -i -e "s/##o1##.##o2##.##o3##.##o4##/$ip/g" /etc/netplan/01-network-manager-all.yaml
netplan apply
sleep 15
sed -i -e "s/##o1##.##o2##.##o3##.##o4##/$ip/g" /home/user/docker-compose.yml
docker-compose up -d
sleep 35
docker exec -i `sudo docker ps | grep -i mysql | cut -d ' ' -f1` /bin/bash -c "mysql -u exampleuser --password=examplepass exampledb -e 'UPDATE wp_options set option_value=\"http://$ip\" WHERE option_name=\"siteurl\";'"
docker exec -i `sudo docker ps | grep -i mysql | cut -d ' ' -f1` /bin/bash -c "mysql -u exampleuser --password=examplepass exampledb -e 'UPDATE wp_options set option_value=\"http://$ip\" WHERE option_name=\"home\";'"
