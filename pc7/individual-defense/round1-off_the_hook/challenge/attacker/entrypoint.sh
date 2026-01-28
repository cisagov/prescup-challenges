#!/bin/bash

# Insert the tokens
sed -i "s|TOKEN|$(echo -n "$reportsWormToken" | base64)|g" /app/worm1.py
sed -i "s|TOKEN|$(echo -n "$publicWormToken" | base64)|g" /app/worm2.py

python3 /app/wormC2.py &

sleep 5  # Give some time for the other containers to boot, just in case

python3 /app/worm1.py
python3 /app/worm2.py

tail -F /dev/null