#!/bin/bash

# Copyright 2025 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.


t1=`vmtoolsd --cmd "info-get guestinfo.t1"`
touch token
echo "$t1" > token

sshpass -p 'Tartans@@1!' scp -o StrictHostKeyChecking=no token root@10.5.5.250:/root/

sshpass -p 'tartans' ssh -o StrictHostKeyChecking=no user@kali-xz 'echo "tartans" | sudo -S date -s "$(date +'%H:%M:%S') May 6 2025"' 
