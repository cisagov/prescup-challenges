#!/bin/bash

# Copyright 2023 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

if [[ $(/usr/bin/id -u) -eq 0 ]]; then
    echo "Error: Please, don't run this script as root."
    exit
fi

####################
####### PREP #######
####################
sudo apt update -y
sudo apt install python3-pip -y
pip install pwntools --no-input

USER=$(logname)
init_path_1=/home/$USER/Desktop/challenge/initialize/part_1
init_path_2=/home/$USER/Desktop/challenge/initialize/part_2

manpass=$(shuf -n 1 $init_path_2/list.txt)

echo $manpass > $init_path_2/managerpass.txt

# Gen private key
openssl genrsa -out $init_path_2/private-key.pem 1024

# Gen public key
openssl rsa -in $init_path_2/private-key.pem -pubout -out $init_path_2/id_rsa.pub

# Remove section of private key
cp $init_path_2/private-key.pem $init_path_2/raw_key.bin

# Leaves prime q so you just need to extract that and modulus N from the public key
python3 -c "print('\x00'*495, end='')" | dd conv=notrunc of=$init_path_2/raw_key.bin bs=495 seek=0

mv -f $init_path_2/raw_key.bin $init_path_2/id_rsa


####################
###### PART 1 ######
####################

### Hide casino file in home directory

sudo cp -r $init_path_1/casino /home/
sudo mv /home/casino /home/.casino

flag1var=$(openssl rand -hex 6)
echo $flag1var > $init_path_2/flag.txt

sudo useradd -m -p $manpass gyre

sudo cp $init_path_2/id_rsa /home/gyre/
sudo cp $init_path_2/id_rsa.pub /home/gyre/
sudo cp $init_path_2/managerpass.txt /home/gyre/
sudo cp $init_path_2/nines /home/gyre/
sudo cp $init_path_2/flag.txt /home/gyre/

sudo chown -R gyre:gyre /home/.casino/*

sudo -u gyre chmod 666 /home/.casino/cash
sudo -u gyre chmod 755 /home/.casino/dice
sudo -u gyre chmod 755 /home/.casino/slots
sudo -u gyre chmod 755 /home/.casino/video_poker
sudo -u gyre chmod 644 /home/.casino/welcome.txt
sudo chmod 4755 /home/.casino/nines

sudo chown -R gyre:gyre /home/gyre

sudo -u gyre chmod 600 /home/gyre/id_rsa
sudo -u gyre chmod 600 /home/gyre/id_rsa.pub
sudo -u gyre chmod 600 /home/gyre/managerpass.txt
sudo -u gyre chmod 600 /home/gyre/flag.txt

####################
###### PART 2 ######
####################

mkdir -p $init_path_1/original_blocks/temp

#Encrypt
cp $init_path_1/original_blocks/original-block1.txt $init_path_1/original_blocks/temp/block1.txt
cp $init_path_1/original_blocks/original-block2.txt $init_path_1/original_blocks/temp/block2.txt
cp $init_path_1/original_blocks/original-block3.txt $init_path_1/original_blocks/temp/block3.txt
cp $init_path_1/original_blocks/original-block4.txt $init_path_1/original_blocks/temp/block4.txt
cp $init_path_1/original_blocks/original-block5.txt $init_path_1/original_blocks/temp/block5.txt
cp $init_path_1/original_blocks/original-block6.txt $init_path_1/original_blocks/temp/block6.txt

flag2var=$(openssl rand -hex 6)
echo $flag2var > $init_path_2/flag2.txt

sed -i "s/%flag2%/$flag2var/g" $init_path_1/original_blocks/temp/block1.txt
sed -i "s/%flag2%/$flag2var/g" $init_path_1/original_blocks/temp/block2.txt
sed -i "s/%flag2%/$flag2var/g" $init_path_1/original_blocks/temp/block3.txt
sed -i "s/%flag2%/$flag2var/g" $init_path_1/original_blocks/temp/block4.txt
sed -i "s/%flag2%/$flag2var/g" $init_path_1/original_blocks/temp/block5.txt
sed -i "s/%flag2%/$flag2var/g" $init_path_1/original_blocks/temp/block6.txt

openssl rsautl -encrypt -inkey $init_path_2/id_rsa.pub -pubin -in $init_path_1/original_blocks/temp/block1.txt -out block1.enc
openssl rsautl -encrypt -inkey $init_path_2/id_rsa.pub -pubin -in $init_path_1/original_blocks/temp/block2.txt -out block2.enc
openssl rsautl -encrypt -inkey $init_path_2/id_rsa.pub -pubin -in $init_path_1/original_blocks/temp/block3.txt -out block3.enc
openssl rsautl -encrypt -inkey $init_path_2/id_rsa.pub -pubin -in $init_path_1/original_blocks/temp/block4.txt -out block4.enc
openssl rsautl -encrypt -inkey $init_path_2/id_rsa.pub -pubin -in $init_path_1/original_blocks/temp/block5.txt -out block5.enc
openssl rsautl -encrypt -inkey $init_path_2/id_rsa.pub -pubin -in $init_path_1/original_blocks/temp/block6.txt -out block6.enc

zip comms.zip block*.enc

cp comms.zip /home/$USER/Desktop/
cp $init_path_1/nines.c /home/$USER/Desktop/


##################################
###### SETTING UP GYRE USER ######
##################################

sudo usermod -aG sudo gyre

cat << EOF > /home/$USER/Desktop/gyre
gyre ALL=(root) /bin/su
EOF

sudo chown root:root /home/$USER/Desktop/gyre
sudo chmod 0440 /home/$USER/Desktop/gyre
sudo deluser gyre sudo
sudo -k
sudo mv /home/$USER/Desktop/gyre /etc/sudoers.d/gyre
sudo -k 

passformat="$manpass\\n$manpass"
echo -e "$passformat" | sudo passwd gyre


################################
###### DISABLING SUDO CMD ######
################################

rootpass="tartans"
passformat="$rootpass\\n$rootpass"
echo -e "$passformat" | sudo passwd root

# Disable user's sudo access
sudo usermod -aG sudo $USER

cat << EOF > /home/$USER/Desktop/$USER
$USER ALL=(root) /bin/su
EOF

sudo chown root:root /home/$USER/Desktop/$USER
sudo chmod 0440 /home/$USER/Desktop/$USER
sudo deluser user sudo
sudo -k
sudo mv /home/$USER/Desktop/$USER /etc/sudoers.d/$USER
sudo -k 
pkill -KILL -u $USER
