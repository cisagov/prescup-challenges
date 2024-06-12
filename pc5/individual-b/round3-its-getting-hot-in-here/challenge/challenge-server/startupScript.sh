#!/bin/bash

# Copyright 2024 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.


software_version=$(vmtoolsd --cmd "info-get guestinfo.software_version")
echo $software_version > software_version.txt

sudo -u user ssh -t -t -o "StrictHostKeyChecking=no" user@10.2.2.100 "echo 'tartans' | sudo -S systemctl stop reactor1.service"
sudo -u user ssh -t -t -o "StrictHostKeyChecking=no" user@10.2.2.100 "echo 'tartans' | sudo -S systemctl stop reactor2.service"

# move software version token to reactor server
scp -i /home/user/.ssh/id_rsa -o "StrictHostKeyChecking=no" ./software_version.txt user@10.2.2.100:/home/user/Documents
echo "Done with scp command for software_version token. Return value was $?"

# enable and start reactor services
sudo -u user ssh -t -t -o "StrictHostKeyChecking=no" user@10.2.2.100 "echo 'tartans' | sudo -S systemctl start reactor1.service"
sudo -u user ssh -t -t -o "StrictHostKeyChecking=no" user@10.2.2.100 "echo 'tartans' | sudo -S systemctl start reactor2.service"

# log that the startup script is done and was successful
echo "Done with startup configuration. All was successful."
