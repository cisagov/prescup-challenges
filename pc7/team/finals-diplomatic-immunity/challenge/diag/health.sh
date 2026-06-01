#!/bin/sh
set -eu

START_DELAY="${DIAG_START_DELAY_SECONDS:-10}"
echo "[diag] waiting ${START_DELAY}s before running checks..."
sleep "$START_DELAY"

echo "[diag] competitor_net routes:"; ip route || true

fail=0
check() { name="$1"; shift
  if "$@"; then echo "✅ $name"; else echo "❌ $name"; fail=1; fi
}

check "intel mbox present" sh -c '
  curl -sf http://intel.embassy.svc:8080/mail/ops.mbox |
  grep -q "SHARD1=" &&
  grep -q "SHARD2=" &&
  grep -q "SHARD3=" &&
  grep -q "END SIGNED MESSAGE"
'
check "surveillance payload exists" sh -c 'curl -sf http://surveillance.embassy.svc:8080/artifacts/payload.cam.enc >/dev/null'
check "archive artifacts exist"     sh -c 'curl -sf http://archive.embassy.svc:8080/artifacts/classified.tar.enc >/dev/null'
check "api-vault docs up (TLS)"     sh -c 'curl -skf https://api-vault.embassy.svc:8443/docs >/dev/null'

# Optional functional probes if tokens are supplied into this diag container
if [ -n "${TOKEN3:-}" ] || [ -n "${TOKEN1:-}" ]; then
  python3 /opt/diag/health.py || fail=1
else
  echo "[diag] tokens not provided to diag; skipping deep checks."
fi

[ "$fail" -eq 0 ] || { echo "[diag] One or more checks failed."; exit 1; }
echo "[diag] All checks passed."
