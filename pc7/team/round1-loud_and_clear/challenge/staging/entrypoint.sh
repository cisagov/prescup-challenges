#!/bin/bash
set -euo pipefail

# ---- Validate runtime tokens (CTFd injects at runtime) ----
# Accept either uppercase TOKEN* or lowercase token* (platform dependent).
for n in 1 2 3 4; do
  up="TOKEN${n}"
  lo="token${n}"
  val="${!up:-${!lo:-}}"
  if [ -z "${val}" ]; then
    echo "[FATAL] Missing required token env var: ${up} (or ${lo})" >&2
    exit 1
  fi
done

# Normalize into uppercase variables for internal use
TOKEN1="${TOKEN1:-${token1:-}}"
TOKEN2="${TOKEN2:-${token2:-}}"
TOKEN3="${TOKEN3:-${token3:-}}"
TOKEN4="${TOKEN4:-${token4:-}}"

mkdir -p /opt/lancer/state /opt/lancer/tokens /var/spool/exim4/input /var/log/exim4 /var/mail

# Write tokens to files (read by qa_hook). Keep permissions tight.
umask 077
echo -n "$TOKEN1" > /opt/lancer/tokens/token1.txt
echo -n "$TOKEN2" > /opt/lancer/tokens/token2.txt
echo -n "$TOKEN3" > /opt/lancer/tokens/token3.txt
echo -n "$TOKEN4" > /opt/lancer/tokens/token4.txt
chmod 0640 /opt/lancer/tokens/token*.txt || true
chown -R Debian-exim:mail /opt/lancer/tokens || true

# Initialize patch state (patchd will also ensure this)
# IMPORTANT: umask 077 was set above for tokens; reset before writing non-secret files.
umask 022

# Ensure directories are traversable by the runtime user (euid=100 egid=101)
chmod 0755 /opt /opt/lancer /opt/lancer/state || true

if [ ! -f /opt/lancer/state/patch_level ]; then
  printf "1\n" > /opt/lancer/state/patch_level
fi

if [ ! -f /opt/lancer/state/banner ]; then
  printf "%s\n" "STAGING — Patch 1 — Legacy QA harness. Raw echo path (no quoting)." > /opt/lancer/state/banner
fi

# Banner is not secret; Exim needs to read it even when running unprivileged.
chmod 0644 /opt/lancer/state/banner



# Start patch control daemon
/usr/bin/python3 /opt/lancer/bin/patchd.py &
echo "[entrypoint] patchd started on :31337"

# Start Exim (daemon)
# Port is controlled by /etc/exim4/exim.conf (2525/tcp)
#/usr/sbin/exim4 -bV || true
# Ensure logs exist BEFORE exim starts (prevents connect-time 421/panic scenarios)
touch /var/log/exim4/mainlog /var/log/exim4/rejectlog /var/log/exim4/paniclog || true
chmod 0644 /var/log/exim4/mainlog /var/log/exim4/rejectlog /var/log/exim4/paniclog || true

/usr/sbin/exim4 -bd -q15m -C /etc/exim4/exim.conf
echo "[entrypoint] exim started on :2525"


# Keep container alive and show logs for debugging
exec tail -F /var/log/exim4/mainlog
