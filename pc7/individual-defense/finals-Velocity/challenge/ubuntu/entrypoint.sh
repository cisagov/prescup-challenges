#!/bin/bash
# Start services
rm -f /entrypoint.sh

/tmp/script0.sh

unset TOKEN1
unset TOKEN2
unset TOKEN3
unset TOKEN4
unset TOKEN5
unset TOKEN6
unset TOKEN7
unset TOKEN8
unset TOKEN9

until curl -k -sS https://velociraptor:8000/reader >/dev/null 2>&1
do
  sleep 5
done
/usr/local/bin/velociraptor_client --config /etc/velociraptor/client.config.yaml client &

exec tail -f /dev/null
