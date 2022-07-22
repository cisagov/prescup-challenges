#!/bin/bash

# Copyright 2022 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

cd /home/$USER/Desktop/challenge

sudo su - << EOF
apt-get update
apt-get install libssl-dev
sed -i "s/UsePAM yes/#UsePAM no/g" /etc/ssh/sshd_config
EOF

PASSWORD=$(hexdump -n 8 -e '4/4 "%08X" 1 "\n"' /dev/urandom)

sed -i "s/PLACEHOLDER/$PASSWORD/g" brute.py

nohup /home/$USER/Desktop/challenge/brute.py &
