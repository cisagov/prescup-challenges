#!/bin/bash

# Copyright 2024 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.


# get transforms and set as variables
index=$(vmtoolsd --cmd "info-get guestinfo.index") # an integer between 1 and 5
g1=$(vmtoolsd --cmd "info-get guestinfo.g1") # [ 7a5492b231075f65cb79 e034c719d927de401afa 18672bfa7ce02c6c27b4 53eeb2698d4dfc27409c ab2518df0ff53cecdac7 ]
guid="${g1:0:5}-${g1:5:10}-${g1:15}"
t1=$(vmtoolsd --cmd "info-get guestinfo.t1") # a 12 character hex string, e.g. ab12cd34ef56
t2=$(vmtoolsd --cmd "info-get guestinfo.t2") # a 12 character hex string, e.g. ab12cd34ef56
its=$(vmtoolsd --cmd "info-get guestinfo.its") # an integer between 10000 and 11000
echo $t2 > /home/user/c28/token2
pwd=$(vmtoolsd --cmd "info-get guestinfo.pwd") # a 32 character hex string, e.g. ab12cd34ef5612ab34cd56ef7890abcd
print $pwd
sha1=`echo -n $pwd | sha1sum | awk '{print $1}'`
md5=`echo -n $pwd | md5sum | awk '{print $1}'`

# shuffle secrets and move to webroot
{ head -n 1 /home/user/c28/secrets.csv; tail -n +2 /home/user/c28/secrets.csv | shuf; } > /home/user/c28/output.csv
sed -i "/^${guid},/s/,[^,]*$/,$t1/" /home/user/c28/output.csv
cp /home/user/c28/output.csv /var/www/secrets/secrets.csv

# Setup vault file and place in hosted_files for download
# replace password with infinity password
sed -i "s/xxxxxxxx/$pwd/g" /home/user/c28/credentials
# Create vault as zip file
zip -j /home/user/c28/vault.zip /home/user/c28/token2 /home/user/c28/credentials
# Encrypt vault file with chosen public key
python3 /home/user/c28/encrypt$index.py >> /home/user/c28/saltlist
key=$(cat /home/user/c28/keyfile | tr -d '\n')
echo $key > /home/user/c28/testkey
openssl enc -aes-256-cbc -in /home/user/c28/vault.zip -out /home/user/c28/vault -pass pass:"$key"
# copy to hosted files
cp /home/user/c28/vault /home/user/challengeServer/hosted_files
openssl enc -aes-256-cbc -d -in /home/user/challengeServer/hosted_files/vault -out /home/user/c28/decrypted-vault -pass pass:"$key"

# Setup Registry XML
secondsalt=$(cat /home/user/c28/newsalt1)
thirdsalt=$(cat /home/user/c28/newsalt2)
fourthsalt=$(cat /home/user/c28/newsalt3)
sed -i "s/GGGG/$guid/g" /home/user/c28/registry$index
sed -i "s/IIII/$its/g" /home/user/c28/registry$index
sed -i "s/HHHH/$md5/g" /home/user/c28/registry$index
sed -i "s/11111111/$secondsalt/g" /home/user/c28/registry$index
sed -i "s/22222222/$thirdsalt/g" /home/user/c28/registry$index
sed -i "s/33333333/$fourthsalt/g" /home/user/c28/registry$index

cp /home/user/c28/registry$index /home/user/challengeServer/hosted_files/registry.xml

# copy artifacts to webroot for files site
# replace expected password hash with the sha1 of infinity generated password
sed -i "s/xxxxxxxx/$sha1/g" /home/user/c28/verify_login.php
# copy files to web directory
#cp /home/user/c28/data$index.zip /var/www/datasite
cp /home/user/c28/verify_login.php /var/www/datasite/verify_login.php

# replace string in document with expected answer
#offset=$(( RANDOM % 3000000 + 4000000 ))
#sed -i "s/\(.\{$offset\}\)/\1$(cat mission-report$index.hex)/" backup4.hex
cp /home/user/c28/backup4_$index.hex /var/www/datasite/storage/backup-feb-27.hex

# restart apache just in case
systemctl reload apache2
service apache2 restart
