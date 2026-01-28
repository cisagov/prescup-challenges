#!/bin/bash
chown -R user:www-data /var/data
chmod 750 /var/data
chmod 750 /var/data/search.sh

service apache2 start
service cron start
service ssh start

tail -F /var/log/apache2/*.log