#!/bin/bash

# Copyright 2024 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.


cd ~/api

while true
do
  ./scripts/up.sh
  if [ $? -eq 0 ]; then
    break
  fi
  echo -e "\e[31mWaiting for the database specified in ~/api.env to be available...\e[0m"
done

echo -e "\e[32mLaunching API server...\e[0m"
./target/release/api
