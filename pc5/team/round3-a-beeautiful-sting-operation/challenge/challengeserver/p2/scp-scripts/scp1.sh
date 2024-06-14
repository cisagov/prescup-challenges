#!/bin/bash

# Copyright 2024 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

ip add flush dev ens35
ip addr add 193.102.176.185/1 dev ens35
ip route add 123.45.67.89 via 128.1.1.1 dev ens35
timeout 15 sshpass -p 'letmeinplz' ssh -b 193.102.176.185 -o StrictHostKeyChecking=no phil@123.45.67.89
sleep 5
timeout 15 sshpass -p 'letmeinplz' ssh -b 193.102.176.185 -o StrictHostKeyChecking=no phil@123.45.67.89
sleep 5
timeout 15 sshpass -p 'letmeinplz' ssh -b 193.102.176.185 -o StrictHostKeyChecking=no phil@123.45.67.89
sleep 5
