#!/bin/sh
set -eu

# Optional: fail early if tokens aren't present (helps catch misconfigured CTFd)
: "${TOKEN1:?TOKEN1 not set}"
: "${TOKEN2:?TOKEN2 not set}"
: "${TOKEN3:?TOKEN3 not set}"
: "${TOKEN4:?TOKEN4 not set}"

mkdir -p /app/etc

# Re-generate staged /app/etc/* at runtime so it matches the injected token
# If stage_etc.sh appends, this ensures consistent output per container start.
# If you want idempotency, you can clear /app/etc first (see note below).
/app/stage_etc.sh

# Hand off to the actual CMD
exec "$@"
