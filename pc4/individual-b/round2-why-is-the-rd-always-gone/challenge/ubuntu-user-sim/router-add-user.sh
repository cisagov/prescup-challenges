#!/bin/bash

# Copyright 2023 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

password='ANYPASSWORDFORUSER'
username='ANYUSERNAMEFORQUESTION1'
password=`echo $password | sed 's/[^a-zA-Z0-9]//g' | tr '[:upper:]' '[:lower:]'`
username=`echo $username | sed 's/[^a-zA-Z0-9]//g' | tr '[:upper:]' '[:lower:]'`
command1="sshpass -p MPnoBIvuCYxtZR ssh -o "UserKnownHostsFile=/dev/null" -o StrictHostKeyChecking=no root@172.21.43.1 'id -u $username && echo 'user exists' && exit || useradd -p $(echo $password | openssl passwd -6 -stdin) $username && echo $username:$password | chpasswd'"
eval "$command1"
