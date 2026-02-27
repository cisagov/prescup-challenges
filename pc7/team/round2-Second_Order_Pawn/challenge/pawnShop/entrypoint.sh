#!/bin/bash

sudo /usr/sbin/sshd

echo "Wait for databases to start"
/usr/bin/wait-for-it --host=pawndata.pccc --port=3306 --timeout=0 --strict
/usr/bin/wait-for-it --host=warehousedata.pccc --port=3306 --timeout=0 --strict

sed -i "s|# TOKEN: _TOKEN_|# TOKEN: ${sourceToken}|" /app/app.py

# exec "$@"
exec gunicorn -b 0.0.0.0:8080 --workers 1 --threads 4 --worker-class gthread --timeout 60 --access-logfile - --error-logfile - app:app
