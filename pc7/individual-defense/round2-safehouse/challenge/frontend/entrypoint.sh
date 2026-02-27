#!/bin/sh
set -eu

API_URL="${VITE_API_URL:-}"

if [ -n "$API_URL" ]; then
  echo "Waiting for API at $API_URL/health ..." >&2
  until curl -fsS "$API_URL/health" >/dev/null 2>&1; do
    sleep 1
  done
fi

# Best-effort: raise file descriptor limit (may be capped by platform)
ulimit -n 65535 2>/dev/null || true

# Force chokidar (used by Vite) to poll, avoiding massive fs.watch usage
export CHOKIDAR_USEPOLLING=true
export CHOKIDAR_INTERVAL=500

# Optional: reduces some extra FS watching noise
export WATCHPACK_POLLING=true

echo "API up, starting frontend..." >&2
exec npm run dev
