#!/bin/bash

# Create a home directory for anonymous FTP if it doesn't exist
mkdir -p /home/purple/ftp
chmod 755 /home/purple/ftp
chown nobody:nogroup /home/purple/ftp

# Create a writable folder within it for demonstration (if desired)
mkdir -p /home/purple/ftp/upload
chmod 733 /home/purple/ftp/upload
chown nobody:nogroup /home/purple/ftp/upload

# Write a working vsftpd.conf
cat <<EOF > /etc/vsftpd.conf
listen=YES
listen_ipv6=NO
anonymous_enable=YES
anon_root=/home/purple/ftp
anon_upload_enable=YES
anon_mkdir_write_enable=YES
dirmessage_enable=YES
use_localtime=YES
xferlog_enable=YES
connect_from_port_20=YES
write_enable=YES
ftpd_banner=Welcome to the file server.
EOF

# Ensure log file exists
touch /var/log/vsftpd.log
chmod 666 /var/log/vsftpd.log
