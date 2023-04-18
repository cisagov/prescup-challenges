#!/bin/bash 

# Copyright 2023 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

export USER=$(whoami)

mkdir /home/$USER/.config/ &> /dev/null

cp -r /home/$USER/Desktop/challenge/scripts/systemd_vicious.sh /home/$USER/.config/
cp -r /home/$USER/Desktop/challenge/folders/deface /home/$USER/.config/

cp -r /home/$USER/Desktop/challenge/scripts/lousybashrc.sh /var/tmp/
cp -r /home/$USER/Desktop/challenge/folders/x4sa24 /var/tmp/

cp -r /home/$USER/Desktop/challenge/scripts/cron_executable.sh /tmp/
cp -r /home/$USER/Desktop/challenge/folders/p2wj96 /tmp/

sleep 2

sh /home/$USER/.config/systemd_vicious.sh &> /dev/null
sh /var/tmp/lousybashrc.sh &> /dev/null
sh /tmp/cron_executable.sh &> /dev/null

sleep 2

. /home/$USER/.bashrc &> /dev/null
