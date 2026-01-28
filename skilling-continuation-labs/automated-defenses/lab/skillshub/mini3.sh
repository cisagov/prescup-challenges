#!/bin/bash

# Copyright 2025 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.


ip link set dev ens34 up
ip addr flush dev ens34
ip addr replace 123.45.67.209/24 dev ens34

# Comment out specific scans for each script file
enum4linux -a -n -S 123.45.67.89
sleep 2
#nikto -h http://123.45.67.89
#sleep 2
nmap -sS -p1-1000 --max-rate 75 123.45.67.89
sleep 2
#ssh-audit 123.45.67.89
#sleep 2
swaks --to victim@honeypot.com --from dusk@darkindex.com --server 123.45.67.89 --header "Subject: Malicious email" --body "Click the attached malicious file please"
sleep 2
swaks --to victim@honeypot.com --from dusk@darkindex.com --server 123.45.67.89 --header "Subject: Malicious email" --body "Click the attached malicious file please"
sleep 2
swaks --to victim@honeypot.com --from dusk@darkindex.com --server 123.45.67.89 --header "Subject: Malicious email" --body "Click the attached malicious file please"
sleep 2
#swaks --to victim@honeypot.com --from theliche@necrobyte.net --server 123.45.67.89 --header "Subject: Malicious email" --body "Click the attached malicious file please"
#sleep 2
#swaks --to victim@honeypot.com --from theliche@necrobyte.net --server 123.45.67.89 --header "Subject: Malicious email" --body "Click the attached malicious file please"
#sleep 2
#swaks --to victim@honeypot.com --from theliche@necrobyte.net --server 123.45.67.89 --header "Subject: Malicious email" --body "Click the attached malicious file please"
#sleep 2
#swaks --to victim@honeypot.com --from ghost@shadowhack.org --server 123.45.67.89 --header "Subject: Malicious email" --body "Click the attached malicious file please"
#sleep 2
#swaks --to victim@honeypot.com --from ghost@shadowhack.org --server 123.45.67.89 --header "Subject: Malicious email" --body "Click the attached malicious file please"
#sleep 2
#swaks --to victim@honeypot.com --from ghost@shadowhack.org --server 123.45.67.89 --header "Subject: Malicious email" --body "Click the attached malicious file please"
#sleep 2
swaks --to victim@honeypot.com --from jakethesnake@venomstrike.io --server 123.45.67.89 --header "Subject: Malicious email" --body "Click the attached malicious file please"
sleep 2
swaks --to victim@honeypot.com --from jakethesnake@venomstrike.io --server 123.45.67.89 --header "Subject: Malicious email" --body "Click the attached malicious file please"
sleep 2
swaks --to victim@honeypot.com --from jakethesnake@venomstrike.io --server 123.45.67.89 --header "Subject: Malicious email" --body "Click the attached malicious file please"
sleep 2

sleep 5

ip addr flush dev ens34
ip link set dev ens34 down


