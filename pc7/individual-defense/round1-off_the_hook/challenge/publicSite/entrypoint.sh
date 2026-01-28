#!/bin/bash
service apache2 start
service cron start
service ssh start

tail -F /var/log/apache2/*.log