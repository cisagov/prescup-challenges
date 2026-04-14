#!/bin/bash

echo "Wait for ssh to start"
/usr/bin/wait-for-it --host=pawnshop.pccc --port=22 --timeout=0 --strict 


echo "Wait for databases to start"
/usr/bin/wait-for-it --host=pawndata.pccc --port=3306 --timeout=0 --strict 
/usr/bin/wait-for-it --host=warehousedata.pccc --port=3306 --timeout=0 --strict 

python /app/insertToken.py

exec "$@"