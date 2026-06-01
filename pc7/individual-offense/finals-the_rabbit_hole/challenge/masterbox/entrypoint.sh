#!/usr/bin/env bash
set -euo pipefail

echo "$mastertoken" > /root/ultimate_token.txt
chmod 600 /root/ultimate_token.txt
chown -R root:root /opt/ctf /root/ultimate_token.txt
cd /opt/ctf

# ensure secrets exist
if [ ! -f ./data/secret.bin ]; then
  python3 make_secret.py ./data/secret.bin
fi

# run service (root recommended inside container so token is protected)
python3 hardnet.py 42424
