FROM ubuntu:22.04

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y \
    vsftpd \
    iptables \
    fail2ban \
    gcc \
    ncat \
    netcat \
    vim \
    sudo \
    checksec \
    iproute2 \
    dnsutils \
    nmap \
    vim \
    nano \
    python3 \
    dos2unix \
    tcpdump \
    inetutils-ping \
    openssh-server gdb ltrace && \
    useradd -m fileuser && echo 'fileuser:gotheextrafile' | chpasswd

# Setup FTP
COPY setup.sh /setup.sh
RUN bash /setup.sh && rm /setup.sh

COPY helper.py /tmp/helper.py
RUN chmod +x /tmp/helper.py
RUN dos2unix /tmp/helper.py
RUN chown fileuser:fileuser /tmp/helper.py

COPY addresses.sh /addresses.sh
RUN dos2unix /addresses.sh
RUN chmod +x /addresses.sh
RUN chown fileuser:fileuser /addresses.sh

RUN touch /var/log/vsftpd.log

# Setup logging
RUN touch /var/log/fake_auth.log && chmod 666 /var/log/fake_auth.log

RUN mkdir -p /var/run/vsftpd/empty
RUN chown -R fileuser:fileuser /home/ftp
RUN chmod 755 /home/ftp

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
RUN dos2unix /entrypoint.sh

EXPOSE 21 20

CMD ["/entrypoint.sh"]
