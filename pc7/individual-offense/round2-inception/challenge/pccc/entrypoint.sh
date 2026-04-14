#!/bin/bash

echo "Infra Token: $tokenConfig" > /app/token.txt

exec python /app/app.py