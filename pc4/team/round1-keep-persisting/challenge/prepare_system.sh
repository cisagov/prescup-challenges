#!/bin/bash

# Copyright 2023 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

if [[ $(/usr/bin/id -u) -ne 0 ]]; then
    echo "Make sure you run script as root."
    exit
fi

LOGGED_USER=$(logname)

if [ "$(dirname "$(readlink -f "$0")")" != "/home/$LOGGED_USER/Desktop/challenge" ]; then
echo "Error: 'challenge' directory and its contents are not located on the desktop!"
echo "Make sure you place the 'challenge' directory on the Desktop before running this script."
exit 1
fi

echo "Challenge directory and its contents are located on the desktop. Running script..."


if ! dpkg -s apache2 &> /dev/null; then
  echo "Installing Apache2 and some dependencies..."
  apt-get update
  apt install binutils -y
  apt-get install apache2 -y
  systemctl enable apache2
  systemctl start apache2
  update-rc.d apache2 defaults
  echo "Apache2 installed."
else
  echo "Apache2 is already installed. Making sure it's enabled and running."
  systemctl enable apache2
  systemctl start apache2
  update-rc.d apache2 defaults
fi

echo "Preparing system for challenge..."
mkdir -p /var/www/html/
chown $LOGGED_USER:$LOGGED_USER -R /var/www/html/

chmod +x deploy_challenge.sh
chmod +x scripts/*
echo "###############################################"
echo "Challenge ready for deployment..."
echo "Run ./deploy_challenge.sh as a regular user to start challenge..."
echo "###############################################"
