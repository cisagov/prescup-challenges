#!/bin/bash
sed -i s/PCCC_ldap_injection_passwd_token/$TOKEN2/ /container/service/slapd/assets/config/bootstrap/ldif/10-people.ldif

exec /container/tool/run
