#!/bin/bash

# Copyright 2023 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

# Generate keys
bash ./genKeys.sh
test $? -eq 0 && echo "Keys generated" || (echo "Error Generating Keys" && exit 1)

# Choose a random user as the key
user_num="45"

# Change path to chosen user's files
path="/home/user/keys/user$user_num/id_rsa"

# Create secret key
openssl rand -out ./secret.key 32

# Encrypt password generation script with secret key
openssl aes-256-cbc -in ./genNewPass.py -out ./encrypted.enc -pass file:./secret.key

# Encrypt secret key with chosen user's private key
openssl rsautl -encrypt -oaep -pubin -inkey <(ssh-keygen -e -f $path -m PKCS8) -in ./secret.key -out ./rsa_key.enc
