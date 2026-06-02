#!/bin/bash
service clamav-daemon start
echo $TOKEN1 > /tmp/token1.txt
unset TOKEN1
/trigger.sh &
sleep 5
/mux.sh &
sleep 5
rm -f /mux.sh
