#!/usr/bin/env sh
set -eu

: "${TOKEN1:? TOKEN1 must be set}"
: "${TOKEN2:? TOKEN2 must be set}"
: "${TOKEN3:? TOKEN3 must be set}"
: "${TOKEN4:? TOKEN4 must be set}"
: "${TOKEN5:? TOKEN5 must be set}"

export TOKEN1 TOKEN2 TOKEN3 TOKEN4 TOKEN5

python3 /app/bootstrap/generate_data.py

exec "$@"
