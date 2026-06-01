#!/bin/bash

echo "$systemToken" > /app/systemToken.txt
echo "$functionToken" > /app/functionToken.txt
echo "$leakToken" > /app/leakToken.txt

exec supervisord -n -c /etc/supervisor/supervisord.conf