#!/bin/sh
set -eu

PCAP_DIR="/opt/yard/telemetry"
PCAP_FILE="$PCAP_DIR/yard_traffic.pcap"
mkdir -p $PCAP_DIR

if [ ! -f "$PCAP_FILE" ]; then
  echo "[*] Generating yard traffic PCAP ($PCAP_PROFILE)..."
  python3 /app/pcap_generator.py
else
  echo "[*] Using existing yard traffic PCAP"
fi

echo "[*] Starting yard gate service"
exec gunicorn \
  --workers 1 \
  --threads 1 \
  --bind 0.0.0.0:8080 \
  yard_gate_service:app

