#!/bin/bash

# Copyright 2023 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

password='ANYPASSWORDFORQUESTION2'
username='ANYUSERNAMEFORQUESTION2'
password=`echo $password | sed 's/[^a-zA-Z0-9]//g' | tr '[:upper:]' '[:lower:]'`
username=`echo $username | sed 's/[^a-zA-Z0-9]//g' | tr '[:upper:]' '[:lower:]'`
command1="sshpass -p $password ssh -o "UserKnownHostsFile=/dev/null" -o StrictHostKeyChecking=no $username@172.21.57.139 'ls'"
eval "$command1"
echo "$command1"
