#!/usr/bin/env bash
set -euo pipefail

for v in TOKEN1 TOKEN2 TOKEN3 TOKEN4 TOKEN5; do
  if [[ -z "${!v:-}" ]]; then
    echo "[FATAL] Missing required env var: $v" >&2
    exit 1
  fi
done

echo "[INFO] Building Arcadian binary with runtime-injected tokens (OFFLINE)..."
export CARGO_NET_OFFLINE=true
cargo build --release --offline

WEBROOT="/var/www/html"
mkdir -p "$WEBROOT"
install -m 0755 /app/target/release/arcadian "$WEBROOT/arcadian"
install -m 0644 /app/static/index.html "$WEBROOT/index.html"

exec apachectl -D FOREGROUND

