#!/bin/bash
sudo -u fileuser ./addresses.sh
service vsftpd start
python3 /tmp/helper.py &

tail -f /usr/sbin/vsftpd /etc/vsftpd.conf