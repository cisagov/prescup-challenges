#!/usr/bin/env bash
set -euo pipefail
: "${TOKEN_T1:?TOKEN_T1 required}"
: "${TOKEN_T2:?TOKEN_T2 required}"
: "${TOKEN_T3:?TOKEN_T3 required}"
: "${TOKEN_T4:?TOKEN_T4 required}"
: "${TOKEN_T5:?TOKEN_T5 required}"

echo "[web] Generating evidence from env tokens..."
export TOKEN_T1 TOKEN_T2 TOKEN_T3 TOKEN_T4 TOKEN_T5
mkdir -p /usr/share/nginx/html/evidence
python3 /app/generator/gen_all.py --out /usr/share/nginx/html/evidence

echo "[web] Starting nginx..."
nginx -g 'daemon off;'
