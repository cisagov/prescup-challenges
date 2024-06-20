#!/bin/bash

# Copyright 2024 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.


sleep 20

# Check if names.txt exists
if [ ! -f '/etc/systemd/system/names.txt' ]; then
  echo "Error: names.txt not found in the current directory."
  exit 1
fi

# Read names from names.txt and run the commands
while IFS= read -r name; do
  echo "Running commands for $name:"
  wallet="${name}_wallet"
  litecoin-cli -regtest loadwallet "$wallet"
  litecoin-cli -regtest -rpcwallet="$wallet" getbalance
  echo '--------------------------------'
done < /etc/systemd/system/names.txt
