#!/bin/bash

# Copyright 2023 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

password='PASSWORDFORipfireADMINALSOINWORDLIST.TXT'
password=`echo $password | sed 's/[^a-zA-Z0-9]//g' | tr '[:upper:]' '[:lower:]'`
command2="sshpass -p MPnoBIvuCYxtZR ssh -o "UserKnownHostsFile=/dev/null" -o StrictHostKeyChecking=no root@172.21.43.1 'cat /var/log/password-changed.txt || { /usr/bin/htpasswd -b -c /var/ipfire/auth/users admin $password ; echo 'web admin password updated' > /var/log/password-changed.txt; reboot; }'"
eval "$command2"
