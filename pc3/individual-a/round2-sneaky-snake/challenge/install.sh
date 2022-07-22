#!/bin/bash 

# Copyright 2022 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.


unzip python3.9.zip
cd $PWD/python3.9
cd logging
sed -i "s/KILL -u user/KILL -u $USER/g" __init__.py
cd ..
sed -i "s/home\/user\/.zshrc/home\/$USER\/.zshrc/g" datetime.py
sed -i "s/echo echo user/echo echo $USER/g" random.py
sudo su - <<EOF
sed -i "s/PATH/#PATH/g" /etc/environment
echo "PYTHONPATH=$PWD" >> /etc/environment
echo "export PYTHONPATH=$PWD" >> ~/.bashrc
export PYTHONPATH=$PWD
EOF
cd ..
sudo su - <<EOF
echo "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:$PWD:/usr/bin:/sbin:/bin:/usr/local/games:/usr/games" >> /etc/environment
source /etc/environment
EOF
reboot
