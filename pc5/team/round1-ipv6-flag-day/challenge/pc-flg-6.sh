#!/usr/bin/bash

# Copyright 2024 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.


# runs from `ncat` listener service

RESP=""

# read nonce (if at least 8 characters long, return hash response):
read NONCE
if (( ${#NONCE} >= 8 )); then
  TOKG=$(vmtoolsd --cmd 'info-get guestinfo.tokg')
  RESP=$(echo "$TOKG:$NONCE" | md5sum | cut -d' ' -f1)
fi

echo "You are connecting from ${NCAT_REMOTE_ADDR} over ipv6 $RESP"
echo
