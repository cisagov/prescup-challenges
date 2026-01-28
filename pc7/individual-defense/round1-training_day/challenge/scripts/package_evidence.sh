#!/bin/bash

if [ -f /challenge/syslog.log ]; then
  echo "[*] syslog.log exists; proceeding."
else
  echo "[!] /challenge/syslog.log not found—skipping log copy."
fi

if [ -f /challenge/disk_image.dd ]; then
  echo "[*] Disk image found; proceeding."
else
  echo "[!] /challenge/disk_image.dd found."
fi

if [ -f /challenge/memory_dump.raw ]; then
  echo "[*] Memory Dump found."
else
  echo "[!] /challenge/memory_dump.raw not found."
fi

if [ -f /challenge/suspicious_capture.pcap ]; then
  echo "[*] PCAP found."
else
  echo "[!] /challenge/suspicious_capture.pcap not found."
fi


chmod 777  /challenge/syslog.log /challenge/memory_dump.raw /challenge/disk_image.dd /challenge/suspicious_capture.pcap /challenge/mission_briefing.txt

tar -czf /challenge/evidence_collection.tar.gz \
    /challenge/syslog.log /challenge/memory_dump.raw /challenge/disk_image.dd /challenge/suspicious_capture.pcap /challenge/mission_briefing.txt
echo "[*] /challenge/evidence_collection.tar.gz created."
