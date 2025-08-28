#!/usr/bin/env bash
set -euo pipefail

##
# This script exists to work-around the fact that
# mysql does not support logging to stdout
#
# This will tail the file logs configured in ./my.cnf
##

LOG_PATHS=(
    '/var/logs/mysql/mysql_error.log'
)

for LOG_PATH in "${LOG_PATHS[@]}"; do
    # https://serverfault.com/a/599209
    ( umask 0 && truncate -s0 "$LOG_PATH" )
    tail --pid $$ -n0 -F "$LOG_PATH" &
done

docker-entrypoint.sh mysqld
