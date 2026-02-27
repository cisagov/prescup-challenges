#!/bin/bash

echo "$updateAccessToken" > /home/user/updateAccessToken.txt

exec /usr/sbin/sshd -D -e -o LogLevel=INFO