#!/bin/bash
set -e

REALM="CTF.LOCAL"
DOMAIN="ctf.local"
BASEDN="dc=ctf,dc=local"

echo "[*] Initializing Kerberos realm ${REALM}"

# Ensure required directories exist
mkdir -p /etc/krb5kdc
mkdir -p /var/lib/krb5kdc

# Only create DB if it doesn't exist (so image can be frozen)
if [ ! -f "/var/lib/krb5kdc/principal" ]; then
  echo "[*] Creating new KDC database..."
  kdb5_util create -s -P 6d0a448e357def2c22d793df26a2eb54 -r ${REALM}
fi

# ACL: allow admin/admin to manage everything
cat > /etc/krb5kdc/kadm5.acl <<EOF
*/admin@${REALM} *
EOF

# ---------------------------------------------------------------------
# Create base principals and seed passwords
# (Using kadmin.local = works before KDC service is running)
# ---------------------------------------------------------------------
echo "[*] Waiting for client1 SSH..."
until ssh -o StrictHostKeyChecking=no -o ConnectTimeout=2 root@client1.${DOMAIN} "true" >/dev/null 2>&1; do
  sleep 3
done

CLIENT_HOST=$(ssh -o StrictHostKeyChecking=no root@client1.${DOMAIN} hostname)

echo "[*] Adding principals..."

kadmin.local -q "addprinc -pw 6d0a448e357def2c22d793df26a2eb54 admin/admin"
kadmin.local -q "addprinc -pw 6d0a448e357def2c22d793df26a2eb54 admin"
kadmin.local -q "addprinc -pw D@mnItB0bby btaylor"
kadmin.local -q "addprinc -pw R00st3r123 ajennings"
kadmin.local -q "addprinc -requires_preauth -pw qwerty jwilliams"
kadmin.local -q "addprinc -pw Day1OG esmith"
kadmin.local -q "addprinc -pw Bon35Jon35 rjones"
kadmin.local -q "addprinc -pw ${TOKEN2} causer"

# Service / host principals
kadmin.local -q "addprinc -randkey host/kdc.${DOMAIN}"
kadmin.local -q "addprinc -randkey host/client1.${DOMAIN}"
kadmin.local -q "addprinc -randkey host/${CLIENT_HOST}"
# kadmin.local -q "addprinc -randkey host/client2.${DOMAIN}"
# kadmin.local -q "addprinc -randkey host/client3.${DOMAIN}"
# kadmin.local -q "addprinc -randkey host/client4.${DOMAIN}"

# ---------------------------------------------------------------------
# Create required keytabs
# ---------------------------------------------------------------------
echo "[*] Creating keytabs..."

# kadmind keytab
kadmin.local -q "addprinc -randkey kadmin/admin"
kadmin.local -q "addprinc -randkey kadmin/changepw"
kadmin.local -q "ktadd -k /etc/krb5kdc/kadm5.keytab kadmin/admin kadmin/changepw"

# KDC host keytab (system location)
kadmin.local -q "ktadd -k /etc/krb5.keytab host/kdc.${DOMAIN}"

# Pre-export host keytabs for clients
kadmin.local -q "ktadd -k /tmp/client1.keytab host/client1.${DOMAIN}"
kadmin.local -q "ktadd -k /tmp/client1.keytab host/${CLIENT_HOST}"
# kadmin.local -q "ktadd -k /tmp/client2.keytab host/client2.${DOMAIN}"
# kadmin.local -q "ktadd -k /tmp/client3.keytab host/client3.${DOMAIN}"
# kadmin.local -q "ktadd -k /tmp/client4.keytab host/client4.${DOMAIN}"

chmod 600 /etc/krb5kdc/kadm5.keytab /etc/krb5.keytab || true

until scp -o StrictHostKeyChecking=no /tmp/client1.keytab root@client1.${DOMAIN}:/etc/krb5.keytab;do sleep 3; done

# scp -o StrictHostKeyChecking=no /tmp/client2.keytab root@client2:/etc/krb5.keytab
# scp -o StrictHostKeyChecking=no /tmp/client3.keytab root@client3:/etc/krb5.keytab
# scp -o StrictHostKeyChecking=no /tmp/client4.keytab root@client4:/etc/krb5.keytab

# ---------------------------------------------------------------------
# Start services
# ---------------------------------------------------------------------
echo "[*] Starting krb5kdc and kadmind..."
/usr/sbin/krb5kdc &
/usr/sbin/kadmind &

sleep 1

# ---------------------------------------------------------------------
# Quick sanity test (optional)
# ---------------------------------------------------------------------
echo "[*] Testing admin principal..."
if kinit admin/admin <<< "6d0a448e357def2c22d793df26a2eb54" >/dev/null 2>&1; then
  echo "    KDC is responding correctly to kinit admin/admin."
else
  echo "    WARNING: kinit admin/admin failed (check logs)."
fi

echo "[*] KDC initialization complete. Keeping container running..."
tail -f /dev/null
