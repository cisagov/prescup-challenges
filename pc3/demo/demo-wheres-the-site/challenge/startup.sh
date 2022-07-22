#!/bin/bash

# Copyright 2022 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.


port=$((($RANDOM + $RANDOM)%58700 + 1300))
token=$(cat /dev/urandom | tr -dc 'a-z0-9' | fold -w 32 | head -n 1)
echo $token > ./token/tokenfile
python3 -m http.server $port --directory ./token


