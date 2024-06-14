#!/bin/bash

# Copyright 2024 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.


token1=`vmtoolsd --cmd 'info-get guestinfo.token1'` # a string, e.g. REDCRANE
file1=`vmtoolsd --cmd 'info-get guestinfo.file1'` # a string, e.g. 17ec
token2=`vmtoolsd --cmd 'info-get guestinfo.token2'` # a string, e.g. WHITEMOOSE
token3=`vmtoolsd --cmd 'info-get guestinfo.token3'` # a string, e.g. BLUEROBIN
token4=`vmtoolsd --cmd 'info-get guestinfo.token4'` # a string, e.g. BLACKQUAIL
bash /etc/systemd/system/place1.sh $token1 $file1
bash /etc/systemd/system/place2.sh $token2
python3 /etc/systemd/system/place3.py $token3
bash /etc/systemd/system/place4-1.sh $token4 favicon
