#!/bin/bash
set -e

echo "[*] Setting up Disks (Challenge 1)"
bash /challenge/generate_disk.sh

echo "[*] Setting up Logs (Challenge 2)"
bash /challenge/generate_logs.sh

echo "[*] Setting up MemDump (Challenge 3)"
bash /challenge/generate_memdump.sh

echo "[*] Setting up RTP Packets (Challenge 4)"
python3 /challenge/generate_RTP.py

# echo "[*] Extra chmod for good measure"

echo "[*] Packing up"
bash /challenge/package_evidence.sh

echo "[*] Copying package into challenge web directory"
cp /challenge/evidence_collection.tar.gz /var/www/html/evidence_collection.tar.gz
cp /challenge/mission_briefing.txt /var/www/html/mission_briefing.txt

echo "[|] Checking for evidence_collection.tar.gz"
bash -c 'ls -lhart /var/www/html/'

# Remove old scripts and artifacts
echo "[*] Removing old scripts..."
rm -f /challenge/generate*.sh /challenge/generate_RTP.py
rm -f /challenge/package_evidence.sh /challenge/suspicious_capture.pcap /challenge/memory_dump.raw /challenge/syslog.log
rm -f /challenge/disk_image.dd
rm -f /challenge/mission_briefing.txt
rm -f /var/www/html/memory_dump.raw  /var/www/html/suspicious_capture.pcap

# Starting WebServer
echo "[*] Starting Apache2"

# Adding Permissions
echo "[*] Correcting permissions..."
chmod 777 /var/www/html/evidence_collection.tar.gz /var/www/html/mission_briefing.txt

# Export APACHE_RUN_DIR for final flight
export APACHE_RUN_DIR=/var/run/apache2
mkdir -p /var/run/apache2

# Execute
apache2ctl -D FOREGROUND
