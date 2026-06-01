FROM ubuntu:20.04

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y \
    vsftpd \
    iptables \
    fail2ban \
    gcc \
    ncat \
    netcat \
    curl \
    vim \
    sudo \
    checksec \
    iproute2 \
    dnsutils \
    nmap \
    vim \
    nano \
    python3 \
    zip \
    dos2unix \
    tcpdump \
    socat \
    openssh-server gdb ltrace && \
    useradd -m ftpuser && echo 'ftpuser:ftpeaceout' | chpasswd

# Setup FTP
COPY setup.sh /setup.sh
RUN dos2unix /setup.sh
RUN bash /setup.sh && rm /setup.sh

RUN touch /var/log/vsftpd.log

# Setup logging
RUN touch /var/log/fake_auth.log && chmod 666 /var/log/fake_auth.log

# Create secure chroot dir
RUN mkdir -p /var/run/vsftpd/empty
RUN chown -R ftpuser:ftpuser /home/ftp
RUN chmod 755 /home/ftp

COPY xcryptzor.c /xcryptzor.c
COPY tools.zip /tools.zip

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
RUN dos2unix /entrypoint.sh

EXPOSE 21 20

CMD ["/entrypoint.sh"]
