#!/bin/bash

# Copyright 2023 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

# token variables
zippassword="antibody"
serverpassword="1111aaaa"
licensekey="2222bbbb"

# create password protected zip file
echo "FTP Server: 10.5.5.160:32210" > passwords
echo "username: scrtftp" >> passwords
echo "password: Km73pDXf" >> passwords
echo "username: user" >> passwords
echo "password: $serverpassword" >> passwords
zip -r -j -P $zippassword share.zip passwords

# create encrypted random beacon value that the game POSTS
beacon="3333cccc"
echo -n $beacon | openssl enc -aes-128-cbc -base64 -nosalt -out ./2048-game/data.txt -K 31373339623430643733366431343838 -iv 37363862343364363137396239663931
zip -r -j ./2048-game/2048Game.zip 2048-game/

# create an image with license key text and move it to a user machine
convert -pointsize 25 -fill yellow -draw "text 300,50 'License Key: $licensekey'" ./license-template.png ./licensekey.jpg

# log that the startup script is done and was successful
echo "Done startup configuration. All was successful."
printf "Files that were generated are:\n ./2048-game/data.txt \n ./2048-game/2048Game.zip \n ./share.zip \n licensekey.jpg"
