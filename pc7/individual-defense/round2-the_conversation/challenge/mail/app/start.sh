#!/bin/bash

echo "[Debug] Starting email generation"

time python /app/src/generate.py -s "$SEED" -m "$MESSAGE_ID"

echo "[Debug] Completed email generation"

cd /data/

echo "[Debug] Starting HTTP server"

python -m http.server 80

# /bin/bash

