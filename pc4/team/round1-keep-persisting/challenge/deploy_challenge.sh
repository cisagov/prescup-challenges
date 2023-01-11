#!/bin/bash

# Copyright 2023 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

if [[ $(/usr/bin/id -u) -eq 0 ]]; then
    echo "Error: Please, don't run this script as root."
    exit
fi

echo "Deploying challenge..."
echo "Preparing default website. You can access it by going to you browser of preference and typing 'localhost'"
echo "Copying backup folder to Desktop."
cp /home/$USER/Desktop/challenge/backups/html_2022/* /var/www/html/
cp -r /home/$USER/Desktop/challenge/backups /home/$USER/Desktop/

echo "Starting attack simulation, please wait..."
./scripts/myStartupScript.sh
echo "Challenge is ready..."
echo "Warn: Make sure you DO NOT remove the 'challenge' directory and its contents from your Desktop since this might affect deployment and/or challenge functionality."
