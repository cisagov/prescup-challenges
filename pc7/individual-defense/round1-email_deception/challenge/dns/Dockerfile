FROM ubuntu:20.04
RUN apt-get update && \
    apt-get install -y bind9 bind9utils sudo openssh-server ssh nano vim && \
    rm -rf /var/lib/apt/lists/*
COPY named.conf.options /etc/bind/named.conf.options
COPY named.conf.local   /etc/bind/named.conf.local
COPY zones              /etc/bind/zones
COPY keys               /etc/bind/zones/keys
COPY entrypoint.sh /var/entrypoint.sh
RUN chmod +x /var/entrypoint.sh
EXPOSE 53/udp 53/tcp 22

RUN useradd -m -s /usr/bin/bash user ; echo "user:mailman" | chpasswd ; usermod -aG sudo user
CMD ["/var/entrypoint.sh"]