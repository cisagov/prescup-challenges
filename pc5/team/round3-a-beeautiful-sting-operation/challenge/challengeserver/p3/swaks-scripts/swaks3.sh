#!/bin/bash

# Copyright 2024 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

ip add flush dev ens35
ip addr add 147.83.45.200/1 dev ens35
ip route add 123.45.67.89 via 128.1.1.1 dev ens35
/usr/bin/swaks --to dave@theship.org --from badguyz@hacks.org --server 123.45.67.89:25 --header "Hey, Buddy" --body "Click this"
