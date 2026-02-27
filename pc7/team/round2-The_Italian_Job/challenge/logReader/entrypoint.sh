#!/bin/bash

echo "$tmcAccessToken" > /home/user/tmcAccessToken.txt
exec /usr/bin/supervisord -c /etc/supervisord.conf