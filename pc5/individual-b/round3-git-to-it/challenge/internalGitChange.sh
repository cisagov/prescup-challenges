#!/bin/bash

# Copyright 2024 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.


status=0

# Loop until the status code is 200
while [ $status -ne 200 ]; do
    # Perform the curl request, ignore SSL certificate validation, and capture the HTTP status code
    status=$(curl -o /dev/null -s -w "%{http_code}" -k https://gitlab.awkward.org/devMan/)
    
    # Check if the status code is not 200
    if [ $status -ne 200 ]; then
        echo "Received status code $status, retrying..."
        sleep 1 # Wait for 1 second
    fi
done

sleep 30

token=$(vmtoolsd --cmd "info-get guestinfo.git")
cd /home/user/challengeServer/custom_scripts/internalproject
sudo -u user git config --global --add safe.directory /home/user/challengeServer/custom_scripts/internalproject
touch token
echo "flag: $token" > token
sudo -u user git add .
sudo -u user git commit -m "flag change"
sudo -u user git push

rm token
sudo -u user git add .
sudo -u user git commit -m "remove flag"
sudo -u user git push
