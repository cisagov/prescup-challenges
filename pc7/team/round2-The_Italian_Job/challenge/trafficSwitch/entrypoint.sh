#!/bin/bash

echo "$cabinetAccessToken" > /root/cabinetAccessToken.txt

mkdir -p /var/run/sshd
chmod 0755 /var/run/sshd
ssh-keygen -A

exec /usr/bin/supervisord -c /etc/supervisord.conf