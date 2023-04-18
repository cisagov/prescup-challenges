#!/bin/bash

# Copyright 2023 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

if [[ $(/usr/bin/id -u) -ne 0 ]]; then
    echo "Must as root ()"
    exit
fi

apt update &&  apt install apache2 -y
rm -rf /var/www/html/*
cp merchantcaste-site/* /var/www/html/
service apache2 restart
service apache2 reload
