FROM ubuntu:24.04

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y \
    iptables \
    git \
    gcc \
    gdb \
    ncat \
    sudo \
    iproute2 \
    curl \
    dnsutils \
    nmap \
    vim \
    nano \
    python3 \
    dos2unix \
    python3-venv python3-pip \
    apache2 apache2-dev \
    vsftpd \
    xinetd telnetd \
    libcurl4-gnutls-dev \
    patchelf \
    openssh-server && \
    useradd -m -s /bin/bash user && echo 'user:password' | chpasswd

RUN adduser user sudo

RUN mkdir -p /time-bandwidths

COPY server /time-bandwidths/server
RUN chmod +x /time-bandwidths/server

COPY welcome.txt /time-bandwidths/welcome.txt

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
RUN dos2unix /entrypoint.sh

RUN mkdir -p /var/run/sshd

EXPOSE 22

ENTRYPOINT ["/entrypoint.sh"]
