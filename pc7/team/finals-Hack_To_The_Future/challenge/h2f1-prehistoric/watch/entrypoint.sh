#!/bin/sh
set -e

python3 /app/mint_cert.py

cp /app/certs/ca.crt /usr/local/share/ca-certificates/ctf-ca.crt && update-ca-certificates

[ "$CLIENT_ID" = "watch404" ] && python3 /app/watch404_dm_poller.py &

exec gunicorn app:app --bind 0.0.0.0:443 --certfile /app/certs/server.crt --keyfile /app/certs/server.key \
  --access-logfile - --error-logfile - --log-level info --timeout 60
