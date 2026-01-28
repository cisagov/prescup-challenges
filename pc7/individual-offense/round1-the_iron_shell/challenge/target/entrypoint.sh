#!/bin/bash
set -e

# 1) Prepare log file
mkdir -p /var/log/secret
touch /var/log/secret/access.log
chmod 644 /var/log/secret/access.log

# 2) Start SSH
service ssh start

#sleep 5

mkdir -p /home/user
until curl -fsSL http://flagserver/token1.txt -o /home/user/token1.txt; do
  echo "flagserver not ready for token1, retrying..."
  sleep 1
done

until curl -fsSL http://flagserver/token3.txt -o /root/token3.txt; do
  echo "flagserver not ready for token3, retrying..."
  sleep 1
done

token=$(curl -s http://flagserver/token4.txt)

# Generate XOR-encrypted bytes for the token
encrypted=$(python3 -c "
flag = b'$token'
encrypted_bytes = ', '.join(f'0x{(b ^ 0xAB):02x}' for b in flag)
print(encrypted_bytes)
")

# Replace the placeholder array with encrypted bytes
sed -i "s|unsigned char encrypted_flag\[\] = {.*};|unsigned char encrypted_flag[] = {$encrypted, 0x00};|" /opt/secret/flag.c
sed -i "s|size_t flag_len = sizeof(encrypted_flag);|size_t flag_len = sizeof(encrypted_flag) - 1;|" /opt/secret/flag.c


gcc -std=gnu11 -O2 -static -s -Wall -o /opt/secret/flag.txt /opt/secret/flag.c
rm /opt/secret/flag.c
chown root:root /opt/secret/flag.txt 
chmod 700 /opt/secret/flag.txt 

# 3) Launch inotify watcher in background

inotifywait -m -e open /opt/secret/flag.txt \
  --format '%T %w%f was opened by PID:%P' --timefmt '%Y-%m-%d %H:%M:%S' \
  >> /var/log/secret/access.log &



# 4) Finally launch Flask
cd /home/user


touch /etc/authbind/byport/8000
chown user /etc/authbind/byport/8000
chmod 755 /etc/authbind/byport/8000



exec sudo -u user authbind --deep python3 /opt/devportal.py
