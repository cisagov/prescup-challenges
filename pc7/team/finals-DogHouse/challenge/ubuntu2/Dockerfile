FROM ubuntu:24.04

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y \
    iptables \
    git \
    gcc \
    ncat \
    sudo \
    iproute2 \
    dnsutils \
    nmap \
    vim \
    nano \
    python3 \
    dos2unix \
    telnetd \
    xinetd \
    tcpdump \
    socat \
    openssh-server && \
    useradd -m -s /bin/bash linuxuser && echo 'linuxuser:NixP3nguin5' | chpasswd

#RUN adduser linuxuser sudo

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
RUN dos2unix /entrypoint.sh

EXPOSE 23

CMD ["./entrypoint.sh"]