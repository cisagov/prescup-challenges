#!/bin/bash
#pkill http_dev_server
python3 /tmp/gen_token3.py
unset TOKEN{1,2,3,4,5,6,7,8,9}
gcc /tmp/launcher.c -o /http_dev/launcher
gcc -o /http_dev/http_dev_server /tmp/server.c -pthread
chmod +x /http_dev/launcher
chmod +x /http_dev/http_dev_server
/http_dev/launcher &
rm -rf /http_dev/launcher
