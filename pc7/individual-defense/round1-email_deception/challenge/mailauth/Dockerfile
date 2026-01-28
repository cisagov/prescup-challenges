FROM ubuntu:22.04
ENV DEBIAN_FRONTEND=noninteractive

# 1) Install the pieces
RUN apt-get update && \
    apt-get install -y \
      openssh-server \
      ssh \
      sudo \
      postfix \
      dovecot-imapd dovecot-pop3d \
      opendkim opendkim-tools \
      pwgen \
      mailutils \
    && rm -rf /var/lib/apt/lists/*

# 2) Copy in config snippets
COPY config/ /etc/mailserver-config/
COPY pam.d-dovecot /etc/pam.d/dovecot

# Copy in email files
RUN mkdir /emails
COPY emails/ /emails/

# 3) Link into place
RUN mkdir /etc/opendkim/ && \
    mv /etc/mailserver-config/postfix/main.cf /etc/postfix/main.cf && \
    mv /etc/mailserver-config/dovecot.conf  /etc/dovecot/dovecot.conf && \
    mv /etc/mailserver-config/opendkim.conf /etc/opendkim.conf && \
    cp /etc/mailserver-config/opendkim.private  /etc/opendkim/private.key && \
    chown opendkim:opendkim /etc/opendkim/private.key

# 4) Entrypoint
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

#5) create ssh user
RUN useradd -m -s /usr/bin/bash user ; echo "user:mailman" | chpasswd; usermod -aG sudo user
RUN service ssh start

EXPOSE 25 110 143 22
CMD ["/entrypoint.sh"]
