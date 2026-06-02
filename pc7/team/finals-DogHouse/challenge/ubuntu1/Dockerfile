FROM ubuntu:24.04

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y \
    iptables \
    git \
    gcc \
    ncat \
    curl \
    sudo \
    iproute2 \
    iputils-ping \
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
    tmux screen \
    clamav clamav-daemon \
    openssh-server && \
    useradd -m -s /bin/bash linuxuser && echo 'linuxuser:NixP3nguin5' | chpasswd


# Setup ClamAV
RUN service clamav-freshclam stop
RUN freshclam
RUN service clamav-freshclam start
#RUN service clamav-daemon start

# Add squid CA to trusted certs
COPY ctf-proxy-ca.pem /usr/local/share/ca-certificates/ctf-proxy-ca.crt
RUN dos2unix /usr/local/share/ca-certificates/ctf-proxy-ca.crt
RUN update-ca-certificates

#RUN mkdir /root/uploads
RUN mkdir -p /uploads
RUN chown clamav:clamav /uploads
RUN chmod 755 /uploads

COPY pub_id_rsa /root/.ssh/authorized_keys
RUN chmod 600 /root/.ssh/authorized_keys
RUN dos2unix /root/.ssh/authorized_keys

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
RUN dos2unix /entrypoint.sh

RUN mkdir -p /var/run/sshd

COPY run.sh /run.sh
RUN dos2unix /run.sh
RUN chmod +x /run.sh

COPY trigger.sh /trigger.sh
RUN dos2unix /trigger.sh
RUN chmod +x /trigger.sh

COPY mux.sh /mux.sh
RUN dos2unix /mux.sh
RUN chmod +x /mux.sh

COPY setup.sh /setup.sh
RUN dos2unix /setup.sh
RUN chmod +x /setup.sh

EXPOSE 22

USER root

CMD ["./entrypoint.sh"]
