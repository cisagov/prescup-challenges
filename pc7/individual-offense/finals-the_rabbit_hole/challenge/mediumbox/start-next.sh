#!/usr/bin/env bash
set -euo pipefail

echo $mediumtoken > token.txt
mkdir -p /run/sshd
ssh-keygen -A

echo "[next] Starting sshd..."
/usr/sbin/sshd -t
exec /usr/sbin/sshd -D
