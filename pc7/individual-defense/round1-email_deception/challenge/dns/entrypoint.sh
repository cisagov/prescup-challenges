#!/bin/bash

service ssh start

named -g -c /etc/bind/named.conf -n 16 &

sleep infinity