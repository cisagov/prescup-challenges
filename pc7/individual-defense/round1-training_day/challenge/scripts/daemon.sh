#!/bin/bash

# Staring Entrypoint
echo "[*] Staring Entrypoint"
bash /challenge/entrypoint.sh

# Deleting Startup Script
echo "[*] Deleting challenge directory"
bash rm -f /challenge/entrypoint.sh


# Clean Up Routine
echo "[*] Cleaning up..."
bash history -c
echo "[*] Environment ready. Happy Hunting, Recruit."

# ──────────────────────────────────────────────
# Prevent the script from exiting so the container stays alive
# ──────────────────────────────────────────────
tail -f /dev/null