#!/usr/bin/env bash
# mail_rogue/entrypoint.sh
set -e

KEY=0x37
HEX_ENC=$(python3 -c 'import sys; flag=sys.argv[1].encode(); key=0x37; print(bytes([b ^ key for b in flag]).hex())' "$token4")
sed -i "s/TOKEN4_PLACEHOLDER_VALUE/$HEX_ENC/" /payloadsrc/payload.c
gcc -O2 -Wall -Wextra -static -s -o /payload/directory.txt /payloadsrc/payload.c


cd /payload && python3 -m http.server 80 &

# Launch Postfix
postfix start-fg