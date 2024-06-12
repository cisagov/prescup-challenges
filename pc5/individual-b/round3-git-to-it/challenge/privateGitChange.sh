#!/bin/bash

# Copyright 2024 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

sleep 30
token=$(vmtoolsd --cmd "info-get guestinfo.developer")
cd /home/user/challengeServer/custom_scripts/private-project
sudo -u user git config --global --add safe.directory /home/user/challengeServer/custom_scripts/private-project
echo "flag: $token" > README.md
sudo -u user git add .
sudo -u user git commit -m "flag change"
sudo -u user git push
