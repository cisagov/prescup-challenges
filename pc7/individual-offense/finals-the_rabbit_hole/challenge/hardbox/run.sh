#!/usr/bin/env bash
set -euo pipefail

echo "[user] Setting up SSH user and environment..."
echo $hardtoken > /home/user/token.txt

if ! id -u user >/dev/null 2>&1; then
  useradd -m -s /bin/bash user
fi

passwd -l user || true

mkdir -p /run/sshd
ssh-keygen -A || true

SSHD=/etc/ssh/sshd_config
if [ -f "$SSHD" ]; then
  sed -i 's/^[#[:space:]]*PasswordAuthentication .*/PasswordAuthentication yes/' "$SSHD" || true
  sed -i 's/^[#[:space:]]*PermitRootLogin .*/PermitRootLogin no/' "$SSHD" || true
  if grep -q '^UsePAM' "$SSHD"; then
    sed -i 's/^UsePAM.*/UsePAM yes/' "$SSHD" || true
  else
    echo 'UsePAM yes' >> "$SSHD"
  fi
fi

echo "[user] Starting sshd..."
/usr/sbin/sshd -t || true
service ssh start || /usr/sbin/sshd &

echo "[user] Launching webapp (Flask) on port 80..."
exec python3 /app/app.py
