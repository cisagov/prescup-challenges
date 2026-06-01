#!/bin/bash
set -euo pipefail

echo $TOKEN3 > /home/admin/token3.txt
chmod 600 /home/admin/token3.txt
chown -R 1100:1100 /home/admin/token3.txt
unset TOKEN3

# NSS to use sss
sed -i 's/^passwd:.*/passwd:         compat sss/' /etc/nsswitch.conf
sed -i 's/^group:.*/group:          compat sss/' /etc/nsswitch.conf
sed -i 's/^shadow:.*/shadow:         compat sss/' /etc/nsswitch.conf

# SSH server 
mkdir -p /var/run/sshd
echo "GSSAPIAuthentication yes" >> /etc/ssh/sshd_config

# Start services
(sssd -i &) || service sssd start || true
/usr/sbin/sshd -D
