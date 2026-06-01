#!/usr/bin/env bash
set -euo pipefail
echo "[web] Enabling SSH (user/password)..."


if ! id -u nech >/dev/null 2>&1; then
  useradd -m -s /bin/bash nech
fi
echo 'nech:ashes' | chpasswd


mkdir -p /run/sshd
ssh-keygen -A


SSHD=/etc/ssh/sshd_config
sed -i 's/^[#[:space:]]*PasswordAuthentication .*/PasswordAuthentication yes/' "$SSHD"
sed -i 's/^[#[:space:]]*PermitRootLogin .*/PermitRootLogin no/' "$SSHD"

if grep -q '^UsePAM' "$SSHD"; then
  sed -i 's/^UsePAM.*/UsePAM yes/' "$SSHD"
else
  echo 'UsePAM yes' >> "$SSHD"
fi
echo "potatoes" >> /home/nech/vork.txt
chown nech:nech /home/nech/vork.txt

echo $easytoken > token.txt

echo "[web] Starting sshd on port 22..."
/usr/sbin/sshd -t
service ssh start
exec python3 /app/app.py
