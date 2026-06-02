#!/bin/bash
sed -i "s/PLACEHOLDER/$TOKEN5/" /xcryptzor.c
gcc -o /home/ftpuser/xcryptzor /xcryptzor.c
chown ftpuser:ftpuser /home/ftpuser/xcryptzor

cp /tools.zip /home/ftpuser/tools.zip
chmod 644 /home/ftpuser/tools.zip
chown ftpuser:ftpuser /home/ftpuser/tools.zip

service vsftpd start

#tail -f /usr/sbin/vsftpd /etc/vsftpd.conf
tail -F /var/log/vsftpd.log
