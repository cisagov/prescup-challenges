#!/bin/bash
service ssh start
service vsftpd start
service apache2 start
gcc -o /http_dev/http_dev_server /http_dev/server.c
rm -f /http_dev/server.c
chmod +x /http_dev/http_dev_server
if [[ var -eq 1 ]]; then
  /tmp/script3.sh
elif [[ var -eq 2 ]]; then
  /tmp/script1.sh
  /tmp/script6.sh
elif [[ var -eq 3 ]]; then
  /tmp/script1.sh
elif [[ var -eq 4 ]]; then
  /tmp/script4.sh 
  /tmp/script5.sh
elif [[ var -eq 5 ]]; then
  /tmp/script2.sh 
  /tmp/script3.sh
elif [[ var -eq 6 ]]; then
  /tmp/script5.sh
elif [[ var -eq 7 ]]; then
  /tmp/script2.sh 
  /tmp/script5.sh
elif [[ var -eq 8 ]]; then
  sleep 1
elif [[ var -eq 9 ]]; then
  /tmp/script7.sh
elif [[ var -eq 10 ]]; then
  /tmp/script4.sh 
  /tmp/script6.sh 
fi

unset TOKEN1
unset TOKEN2
unset TOKEN3
unset TOKEN4
unset TOKEN5
unset TOKEN6
unset TOKEN7
unset TOKEN8
unset TOKEN9

/http_dev/http_dev_server &

rm -rf /tmp/*
