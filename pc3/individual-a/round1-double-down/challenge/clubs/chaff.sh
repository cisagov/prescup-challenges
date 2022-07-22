#!/bin/env bash

# Copyright 2022 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

sudo hping3 -c 1 -n diamonds -e "For anyone who also loves book, ill be sending out a file with a site that hosts free books for the public!!"
sleep 15
sudo hping3 -c 1 -n spades -e "For anyone who also loves book, ill be sending out a file with a site that hosts free books for the public!!"
sleep 15
sudo hping3 -c 1 -n hearts -e "For anyone who also loves book, ill be sending out a file with a site that hosts free books for the public!!"
sleep 30


scp ./site.txt user@diamonds:Desktop/
sleep 20
scp ./site.txt user@spades:Desktop/
sleep 20
scp ./site.txt user@hearts:Desktop/
sleep 30
