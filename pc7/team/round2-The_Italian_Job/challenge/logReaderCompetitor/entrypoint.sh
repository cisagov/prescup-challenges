#!/bin/bash
/usr/bin/supervisord -c /etc/supervisord.conf

tail -f /var/log/supervisor/log.txt 