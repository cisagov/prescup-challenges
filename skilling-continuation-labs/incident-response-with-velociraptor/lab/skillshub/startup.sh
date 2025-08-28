#!/bin/bash

# Copyright 2025 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.


q3=$(vmtoolsd --cmd "info-get guestinfo.q3")
q4=$(vmtoolsd --cmd "info-get guestinfo.q4")
filename=$(vmtoolsd --cmd "info-get guestinfo.filename")

echo $q3 >> /home/user/s14/$filename
echo $q4 >> /home/user/s14/sus.ini
