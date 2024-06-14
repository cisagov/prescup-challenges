#!/bin/bash

# Copyright 2024 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.


key=`vmtoolsd --cmd "info-get guestinfo.secretkey"`
sed s/SECRETKEY/$key/g /etc/systemd/system/deploy/pre-gold.txt > /etc/systemd/system/deploy/gold.txt
