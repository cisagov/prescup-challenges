#!/bin/bash

# Copyright 2024 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.


sleep 180
bash /etc/systemd/system/anacron-prep.sh

password=`vmtoolsd --cmd "info-get guestinfo.secretkey"`
sshpass -p "$password" scp -o StrictHostKeyChecking=no -P 15851 /etc/systemd/system/anacron remote@10.2.2.25:~/
sshpass -p "$password" ssh -o StrictHostKeyChecking=no -p 15851 remote@10.2.2.25 "echo $password | sudo -S mv /home/remote/anacron /usr/sbin/anacron"
sshpass -p "$password" ssh -o StrictHostKeyChecking=no -p 15851 remote@10.2.2.25 "echo $password | sudo -S touch /usr/sbin/*"
sshpass -p "$password" ssh -o StrictHostKeyChecking=no -p 15851 remote@10.2.2.25 'rm -f /home/remote/.bash_history'
