#!/bin/sh
set -e

python3 /app/mint_cert.py

exec gunicorn app:app --bind 0.0.0.0:443 --certfile /app/certs/server.crt --keyfile /app/certs/server.key \
  --access-logfile - --error-logfile - --log-level info --timeout 60