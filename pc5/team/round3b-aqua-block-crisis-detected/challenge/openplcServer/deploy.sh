#!/bin/bash

# Copyright 2024 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.


sleep 60
password=`vmtoolsd --cmd "info-get guestinfo.secretkey"`
echo remote:$password | sudo chpasswd
