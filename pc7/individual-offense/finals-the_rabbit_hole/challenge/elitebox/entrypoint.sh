#!/usr/bin/env bash
set -euo pipefail
cd /opt/elitebox
echo $elitetoken > /root/ultimate_token.txt
# run services as background tasks
# net service -> port 31337
nohup python3 netservice.py 31337 >/var/log/netservice.log 2>&1 &

# wasm runner -> port 8080
nohup python3 wasm_server.py 8080 >/var/log/wasm_server.log 2>&1 &

# crypto vault (unix socket) -> we'll run it with restricted permissions
nohup python3 crypto_vault.py /tmp/crypto.sock >/var/log/crypto_vault.log 2>&1 &

# small supervisor loop (keep container alive)
sleep infinity
