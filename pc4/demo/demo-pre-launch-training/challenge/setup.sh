#!/bin/bash

# Copyright 2023 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

# Generate files for token2 and activation code
token2="ThisIsToken2"
echo $token2 > token2
act_code="YourActivationCode"
echo $act_code > activation_code

# Create a zip file containing token2
zip -P Dauntless unzip_me.zip token2 activation_code

echo "Done startup configuration. All was successful."
