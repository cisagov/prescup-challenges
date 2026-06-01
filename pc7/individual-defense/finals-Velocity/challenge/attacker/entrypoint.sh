#!/bin/bash
/connect.sh 
sed -i 's/#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
/usr/sbin/sshd -D
