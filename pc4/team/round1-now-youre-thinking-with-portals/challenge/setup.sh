#! /bin/bash

# Copyright 2023 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

### Get Tokens ###
echo "aaaaaaaa" | tr -d '\n'  > ./token1.txt
echo "bbbbbbbb" | tr -d '\n'  > ./token2.txt
echo "cccccccc" | tr -d '\n'  > ./token3.txt
echo "dddddddd" | tr -d '\n'  > ./token4.txt
echo "eeeeeeee" | tr -d '\n'  > ./token5.txt

 ### Push Flags ###
cp  ./token1.txt /var/www/html/tmp
cp  ./token2.txt /var/www/html/tmp
cp  ./token3.txt /var/www/html/tmp
cp  ./token4.txt /var/www/html/tmp
cp  ./token5.txt /var/www/html/tmpadminapi
