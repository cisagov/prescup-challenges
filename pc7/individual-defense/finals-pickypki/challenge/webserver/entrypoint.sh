#!/usr/bin/env bash
set -Eeuo pipefail

CERT_DIR=${CERT_DIR:-/etc/nginx/certs}
LIVE_DIR=${LIVE_DIR:-/runtime-certs}

echo "[web] Using CERT_DIR=$CERT_DIR LIVE_DIR=$LIVE_DIR"
mkdir -p "$CERT_DIR"

# Use challenger-provided certs if present; otherwise mint a 1-day self-signed cert.
if [[ -f "$LIVE_DIR/server.crt" && -f "$LIVE_DIR/server.key" ]]; then
  echo "[web] Using challenger-provided certs from $LIVE_DIR"
  cp -f "$LIVE_DIR/server.crt" "$CERT_DIR/server.crt"
  cp -f "$LIVE_DIR/server.key" "$CERT_DIR/server.key"
else
  echo "[web] No certs supplied; generating self-signed (untrusted) cert"
  echo "[web] openssl: $(openssl version)"
  openssl req -x509 -nodes -newkey rsa:2048 \
    -subj "/CN=webserver" \
    -keyout "$CERT_DIR/server.key" \
    -out "$CERT_DIR/server.crt" \
    -days 1 -sha256
fi

# Tighten perms (good hygiene)
chmod 600 "$CERT_DIR/server.key" || true
chmod 644 "$CERT_DIR/server.crt" || true

# Start SSH if available
if command -v sshd >/dev/null 2>&1; then
  echo "[web] Enabling SSH (user/password)..."
  
  # Ensure the password is set (idempotent)
  echo 'user:password' | chpasswd || true

  mkdir -p /run/sshd
  ssh-keygen -A

  # Ensure password auth is on and root login is off
  if grep -qE '^\s*PasswordAuthentication' /etc/ssh/sshd_config; then
    sed -i 's/^\s*#\?\s*PasswordAuthentication .*/PasswordAuthentication yes/' /etc/ssh/sshd_config
  else
    echo 'PasswordAuthentication yes' >> /etc/ssh/sshd_config
  fi
  if grep -qE '^\s*PermitRootLogin' /etc/ssh/sshd_config; then
    sed -i 's/^\s*#\?\s*PermitRootLogin .*/PermitRootLogin no/' /etc/ssh/sshd_config
  else
    echo 'PermitRootLogin no' >> /etc/ssh/sshd_config
  fi
  if grep -qE '^\s*UsePAM' /etc/ssh/sshd_config; then
    sed -i 's/^\s*UsePAM .*/UsePAM no/' /etc/ssh/sshd_config
  else
    echo 'UsePAM no' >> /etc/ssh/sshd_config
  fi

  /usr/sbin/sshd -t && /usr/sbin/sshd
  echo "[web] sshd is up on port 22"
fi

echo "[web] Starting nginx..."
exec nginx -g 'daemon off;'
