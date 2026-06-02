FROM ubuntu:22.04

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y \
    iptables \
    git \
    gcc \
    ncat \
    netcat \
    curl \
    sudo \
    iproute2 \
    dnsutils \
    nmap \
    vim \
    nano \
    python3 \
    zip \
    dos2unix \
    telnet \
    ftp \
    expect \
    tcpdump \
    rsyslog \
    lsof \
    openssh-server && \
    useradd -m -s /bin/bash ops-user && echo 'ops-user:secret0psP@ssw0rd444!123' | chpasswd

RUN adduser ops-user sudo

RUN mkdir -p /home/ops-user/.ssh
RUN chmod 700 /home/ops-user/.ssh
COPY id_rsa.pub /home/ops-user/.ssh/authorized_keys
RUN chmod 600 /home/ops-user/.ssh/authorized_keys
RUN chown -R ops-user:ops-user /home/ops-user/.ssh
RUN dos2unix /home/ops-user/.ssh/authorized_keys

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
RUN dos2unix /entrypoint.sh

COPY setup.sh /setup.sh
RUN chmod +x /setup.sh
RUN dos2unix /setup.sh

RUN mkdir -p /var/run/sshd

EXPOSE 22

CMD ["./entrypoint.sh"]
