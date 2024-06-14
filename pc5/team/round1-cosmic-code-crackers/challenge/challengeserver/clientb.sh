#!/bin/bash

# Copyright 2024 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

name=$(vmtoolsd --cmd "info-get guestinfo.n2") # one of these at random; amber felix kevin tyler zelda eliza kiera lyric rowan aiden chase dylan fiona greta haley jaden oscar diane
pass1=$(vmtoolsd --cmd "info-get guestinfo.p1") # one of these at random; jkqwx gzxpk rhlqt byvju opnxs dfrwj ixgvt nfzhy cqvks lmypd ugsrk aoxzt bcyqv ejmtx dnlwi fhtgy kxsja rzlnw uvfqm ytkwj gcsli amnxb ozwjp pyqhv dkxrn
pass2=$(vmtoolsd --cmd "info-get guestinfo.p2") # one of these at random; jgvfs eqmwy cnbzt fudap lhxse ykjnb iumvp rxqao swnlt ztpjy vbmfk gylhx qfktj onwce zjxvk hdulm pizfy awtqc krsfn evmub nbfgj xqoiy tcjhu zvlwy uskxd
dir=$(vmtoolsd --cmd "info-get guestinfo.d2") # one of these at random; /usr/share/calendar /usr/share/color /usr/share/dict /usr/share/fonts /usr/lib/apt /usr/lib/bluetooth /usr/lib/gcc /usr/lib/grub /usr/share/bug /usr/share/alsa
token=$(vmtoolsd --cmd "info-get guestinfo.t2") # a 12 character hex string, e.g. 12ab34cd56ef

echo -n $name > /home/user/c03/crypto/name
echo -n $pass1 > /home/user/c03/crypto/pass1
echo -n $pass2 >> /home/user/c03/crypto/pass2
echo -n $pass1 > /home/user/c03/crypto/password
echo -n $pass2 >> /home/user/c03/crypto/password
echo -n $token > /home/user/c03/crypto/token

#sed replace based on mapping for 3 files above
/home/user/c03/crypto/sub.sh

#sed replace strings into crypto files
cryptn=$(cat /home/user/c03/crypto/name)
cryptp1=$(cat /home/user/c03/crypto/pass1)
cryptp2=$(cat /home/user/c03/crypto/pass2)
sed -i "s/#####/$cryptn/g" /home/user/c03/crypto/user.c
sed -i "s/#####/$cryptp1/g" /home/user/c03/crypto/pwd-p1.c
sed -i "s/#####/$cryptp2/g" /home/user/c03/crypto/pwd-p2.c

#Compile code
gcc /home/user/c03/crypto/user.c -o /home/user/c03/crypto/user.exe
gcc /home/user/c03/crypto/pwd-p1.c -o /home/user/c03/crypto/pwd-p1.exe
gcc /home/user/c03/crypto/pwd-p2.c -o /home/user/c03/crypto/pwd-p2.exe

#create token zip with password
password=$(cat /home/user/c03/crypto/password)
zip -P $password -r /home/user/c03/crypto/token.zip /home/user/c03/crypto/token
mv /home/user/c03/crypto/token.zip /home/user/c03/crypto/$name/token.zip

#connect and wait if not ready
nc -zv 10.2.2.50 22 > /dev/null

while [ $? -eq 1 ]
do
    echo "sleeping"
    sleep 5
    nc -zv 10.2.2.50 22 > /dev/null
done

#Create user directories and move zips
for n in amber felix kevin tyler zelda eliza kiera lyric rowan aiden chase dylan fiona greta haley jaden oscar diane
do
    ssh user@10.2.2.50 "echo 'tartans' | sudo -S mkdir /home/$n"
    scp -i /home/user/.ssh/id_rsa -O "StrictHostKeyCheck=no" /home/user/c03/crypto/$n/token.zip user@10.2.2.50:/home/user/
    ssh user@10.2.2.50 "echo 'tartans' | sudo -S mv /home/user/token.zip /home/$n/"
done

#Move program files to directory
scp -i /home/user/.ssh/id_rsa -O "StrictHostKeyCheck=no" /home/user/c03/crypto/*.exe user@10.2.2.50:/home/user/
ssh user@10.2.2.50 "echo 'tartans' | sudo -S mv /home/user/*.exe $dir/"

#Timestomp
ssh user@10.2.2.50 "echo 'tartans' | sudo -S touch -a -m -r /usr/share/calendar/calendar.argentina $dir/*"
ssh user@10.2.2.50 "echo 'tartans' | sudo -S touch -a -m -r /usr/share/calendar/calendar.argentina /home/$name/token.zip"
