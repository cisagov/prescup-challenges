#!/bin/bash

# Create a home directory for FTP if it doesn't exist
mkdir /home/ftp
chmod 755 /home/ftp
chown ftpuser:ftpuser /home/ftp

# Write a working vsftpd.conf
cat <<EOF > /etc/vsftpd.conf
listen=YES
listen_ipv6=NO
anonymous_enable=NO
local_enable=YES
local_root=/home/ftpuser
user_sub_token=ftpuser
write_enable=YES
download_enable=YES
dirmessage_enable=YES
use_localtime=YES
xferlog_enable=YES
connect_from_port_20=YES
chroot_local_user=YES
allow_writeable_chroot=YES
secure_chroot_dir=/var/run/vsftpd/empty
pam_service_name=vsftpd
ftpd_banner=Welcome to the file server.
EOF

# Ensure log file exists
touch /var/log/vsftpd.log
chmod 666 /var/log/vsftpd.log
