#!/bin/bash

echo "Wait for mongo start"
/usr/bin/wait-for-it --host=mongo --port=27017 --timeout=30 --strict

python3 /app/init.py
while true; do
    python3 /app/support.py
    sleep 10
done