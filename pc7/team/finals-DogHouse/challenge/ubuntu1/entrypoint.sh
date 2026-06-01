#!/bin/bash
rm -rf entrypoint.sh
/setup.sh
rm -f /setup.sh

unset TOKEN1

# Start the ssh server
service ssh start

exec tail -f /dev/null
