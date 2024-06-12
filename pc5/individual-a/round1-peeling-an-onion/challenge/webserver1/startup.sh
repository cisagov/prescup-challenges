#!/bin/bash

# Copyright 2024 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.


# seed the db and deploy container


token1=$(vmtoolsd --cmd "info-get guestinfo.adminpass")

Editing=##adminpass##

if [[ $token1 = $Editing ]] ; then

    echo Editing Challenge in TM in Templates

else
    docker image rm diwa
    #### NOTE! The diwa default settings are changed.  
    #### the db file has had the diwa_ prefix removed on table names 
    #### and the config has changed to reflect this.
    python3 /home/user/diwa/database/dbseed.py
    sleep 20
    cd /home/user/diwa
    docker build -t diwa .
    
fi
    docker run -p 80:80 -d diwa:latest

