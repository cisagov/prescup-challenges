#!/usr/bin/env sh
set -eu

# Require tokens (adjust if TOKEN5 isn’t used)
: "${TOKEN1:?}"; : "${TOKEN2:?}"; : "${TOKEN3:?}"; : "${TOKEN4:?}"
: "${TOKEN5:=}"

# Cert/key paths baked into the image at build time
CERT="${SSL_CERTFILE:-/etc/ssl/api-vault/server.crt}"
KEY="${SSL_KEYFILE:-/etc/ssl/api-vault/server.key}"

# Fail fast if certs are missing (no runtime writes in read-only containers)
[ -r "$CERT" ] && [ -r "$KEY" ] || {
  echo "FATAL: missing TLS cert/key at $CERT and/or $KEY" >&2
  exit 111
}

# Tunables via env with safe defaults
: "${UVICORN_WORKERS:=2}"
: "${UVICORN_LIMIT_CONCURRENCY:=128}"
: "${UVICORN_BACKLOG:=2048}"
: "${UVICORN_TIMEOUT_KEEPALIVE:=15}"
: "${UVICORN_LOG_LEVEL:=info}"
: "${UVICORN_EXTRA_ARGS:=}"

exec uvicorn app.main:app \
  --host 0.0.0.0 \
  --port 8443 \
  --ssl-certfile "$CERT" \
  --ssl-keyfile "$KEY" \
  --workers "$UVICORN_WORKERS" \
  --limit-concurrency "$UVICORN_LIMIT_CONCURRENCY" \
  --backlog "$UVICORN_BACKLOG" \
  --timeout-keep-alive "$UVICORN_TIMEOUT_KEEPALIVE" \
  --log-level "$UVICORN_LOG_LEVEL" \
  $UVICORN_EXTRA_ARGS

