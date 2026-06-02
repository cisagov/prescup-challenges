#!/usr/bin/env bash
set -e

# Only start if HOSTS_JSON is set AND valid JSON; otherwise do nothing (including NOT starting CoreDNS)
if [ -n "${HOSTS_JSON:-}" ] && echo "$HOSTS_JSON" | jq -e . >/dev/null 2>&1; then 
    DNS_ON="true"
    echo "[entrypoint] HOSTS_JSON present + valid; starting DNS generator..."
    # Right now, we just run once. It could be modified to run regularly, but that would fill network with nmap scans
    COREDNS_DIR=/app/dns /app/dns/genzones.py

    echo "[entrypoint] Starting CoreDNS..."
    GOMAXPROCS=12 coredns -conf /app/dns/Corefile > /app/dns/coredns.log 2>&1 &

    # Check if we should use our own dns on this server.
    #   Note you can copy this while loop into other challenges. Tries both known challenge server names
    if [ -n "${USE_OWN_DNS:-}" ]; then
        while true; do
            IP=$(dig +short challenge.pccc A | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | head -n1)

            if [ -n "$IP" ]; then
                printf "nameserver $IP\nnameserver 127.0.0.11\noptions ndots:0\n" > /etc/resolv.conf
                echo "Resolved challenge.pccc to $IP and using as DNS server"
                break
            fi

            IP=$(dig +short challenge.us A | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | head -n1)

            if [ -n "$IP" ]; then
                printf "nameserver $IP\nnameserver 127.0.0.11\noptions ndots:0\n" > /etc/resolv.conf
                echo "Resolved challenge.us to $IP and using as DNS server"
                break
            fi

            echo "DNS not available yet, retrying..."
            sleep 5
        done
    fi
else
    echo "[entrypoint] HOSTS_JSON missing or invalid; skipping DNS generator and CoreDNS."
    DNS_ON="false"
fi


echo "[entrypoint] Starting challenge server..."
exec python /app/challengeServer.py
