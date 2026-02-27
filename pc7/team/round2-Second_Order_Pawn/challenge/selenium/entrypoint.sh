#!/bin/bash

echo "Wait for databases to start"
/usr/bin/wait-for-it --host=pawndata.pccc --port=3306 --timeout=0 --strict
/usr/bin/wait-for-it --host=warehousedata.pccc --port=3306 --timeout=0 --strict

while true; do
    python3 /app/admin.py
    python3 /app/spy.py
    sleep 10
done