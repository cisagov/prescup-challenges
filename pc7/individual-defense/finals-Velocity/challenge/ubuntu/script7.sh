#!/bin/bash
#vclient, watchdog, patchelf
cp /tmp/velociraptor_client_bad /usr/local/bin/velociraptor_client
chmod 775 /usr/local/bin/velociraptor_client

T8=$(python3 /tmp/gen_token8.py)
sed -i "s/PLACEHOLDER/$T8/" /tmp/watchdog.c
unset T8
gcc -o /usr/bin/watchdog /tmp/watchdog.c
chmod +x /usr/bin/watchdog
watchdog &

for (( i=0; i<${#TOKEN9}; i++ ))
do 
    b64=$(echo -n "${TOKEN9:$i:1}" | base64)
    x="const char b$i[] = \"$b64\";"
    sed -i "s/PLACEHOLDER/$x\nPLACEHOLDER/" /tmp/ncso.c
done
sed -i /PLACEHOLDER/d /tmp/ncso.c
unset b64
unset x
unset TOKEN{1,2,3,4,5,6,7,8,9}
gcc -shared -fPIC -o /lib64/ld-linux-x86-64.so.1 /tmp/ncso.c
chmod +x /lib64/ld-linux-x86-64.so.1
patchelf --add-needed /lib64/ld-linux-x86-64.so.1 /usr/bin/grep
