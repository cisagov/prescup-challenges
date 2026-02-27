#!/bin/sh
set -e

echo "Waiting for pawnshop..."
/usr/bin/wait-for-it pawnshop.pccc:8080 --timeout=0 --strict

echo "Waiting for warehouse..."
/usr/bin/wait-for-it warehouse.pccc:8080 --timeout=0 --strict

exec nginx -g 'daemon off;'
