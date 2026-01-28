#!/bin/sh

service ssh start
sleep 5

curl -s "http://flagserver/token2.txt" > /token.txt

python3 /service.py