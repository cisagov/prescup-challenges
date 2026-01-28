#!/bin/bash

service ssh start
service vsftpd start

sleep 5

curl -s http://flagserver/token1.txt >> /home/purple/ftp/token/token.txt

tail -f /usr/sbin/vsftpd /etc/vsftpd.conf