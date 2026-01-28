#!/bin/bash
set -e

# 1) Generate 3 random users, all with password "mailman"
for i in 1 2 3 4 5 6; do
  USER=$(pwgen -s 8 1 | tr '[:upper:]' '[:lower:]')
  echo "→ Creating system user: $USER"
  useradd -m -s /usr/bin/bash $USER
  echo "$USER:mailman" | chpasswd
  # Initialize Maildir
  mkdir -p /home/$USER/Maildir/{cur,new,tmp}
  chown -R $USER:dovecot /home/$USER/Maildir
  chmod -R 700 /home/$USER/Maildir
  mv /emails/email$i.eml /home/$USER/Maildir/new/
#  mv /emails/email$($i + 3).eml /home/$USER/Maildir/new
done

# add user


# 2) Ensure Dovecot can see our users’ Maildirs under /home
# chown -R root:dovecot /home/*/Maildir
# chmod -R 770 /home/*/Maildir

# 3) Start services
service opendkim start
service postfix start
service dovecot start
service ssh start

# 4) Keep container alive and show mail log
tail -F /var/log/mail.log
