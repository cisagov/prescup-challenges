#!/bin/bash

# Copyright 2022 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

file="../challenge/wordlist.txt"
echo "start"
lines=$(cat $file)
for line in $lines
do
 echo -e $line | tr -d '\n' | gpg --pinentry-mode=loopback --batch --yes --quiet --passphrase-fd 0 --armor --output out.tar.gz --decrypt ../Desktop/well.tar.gz.gpg
 if [ $? -eq 0 ]; then
  echo "found password $line"
  exit
 fi
done
