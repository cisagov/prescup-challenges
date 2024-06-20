#!/bin/bash

# Copyright 2024 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

while : 
do
    sleep 10
    sudo hping3 -c 1 -n 123.45.67.222 -e "Please note, Firewall credentials have been updated to:  admin::Wyl1eCaGe" -1
done

