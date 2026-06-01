#!/bin/bash

TARGET_HOST="${TARGET_HOST:-perfectdark.fut.pccc}"
TARGET_PORT=22

echo "[*] Waiting for SSH on ${TARGET_HOST}:${TARGET_PORT} ..."

until nc -z "${TARGET_HOST}" "${TARGET_PORT}" >/dev/null 2>&1; do
    echo "[*] SSH not up yet, retrying..."
    sleep 2
done

echo "[+] SSH reachable on ${TARGET_HOST}:${TARGET_PORT}"
exit 0
