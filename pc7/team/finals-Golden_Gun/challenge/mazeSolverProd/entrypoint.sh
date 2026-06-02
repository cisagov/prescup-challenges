#!/usr/bin/env bash
set -uo pipefail

echo "[entry] Seeding DB ..."
attempt=0
while true; do
  /app/db_seed.py
  rc=$?
  if [ $rc -eq 0 ]; then
    echo "[entry] Seed succeeded."
    break
  fi
  attempt=$((attempt+1))
  echo "[entry] Seed failed (rc=$rc). Retry in 5s... (attempt $attempt)"
  sleep 5
done

# Hand off to the stock PHP-Apache entrypoint/cmd
exec /usr/local/bin/docker-php-entrypoint apache2-foreground
