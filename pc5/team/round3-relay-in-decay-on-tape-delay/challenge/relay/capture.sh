#!/bin/bash

# Copyright 2024 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.


date=$(date +'%d%m%Y%H%M')

echo "tartans" | sudo -s timeout 55 tcpdump -i eth1 -w "/home/user/captures/$date.pcapng" "src host 10.10.10.100 and dst host 10.10.10.101 and tcp"

cd /home/user/captures
ls -t | grep -vF token1 | tail -n +5 | xargs rm -rf
