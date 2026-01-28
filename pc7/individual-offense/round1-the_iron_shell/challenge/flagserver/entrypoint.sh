#!/bin/bash

echo $token1 > token1.txt
echo $token3 > token3.txt
echo $token4 > token4.txt

python3 flagserve.py

rm /token1.txt
rm /token3.txt
rm /token4.txt

sleep infinity