FROM ubuntu:20.04

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y \
    iptables \
    git \
    gcc \
    netcat \
    sudo \
    iproute2 \
    dnsutils \
    nmap \
    vim \
    nano \
    python3 \
    dos2unix \
    ansible \
    openssh-server && \
    useradd -m -s /bin/bash user1 && echo 'user1:password1' | chpasswd

RUN adduser user1 sudo

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
RUN dos2unix /entrypoint.sh

COPY setup.sh /setup.sh
RUN chmod +x /setup.sh
RUN dos2unix /setup.sh

RUN mkdir -p /var/run/sshd

RUN mkdir -p /home/user1/backups

COPY pass.txt /pass.txt
RUN dos2unix /pass.txt
RUN chmod 600 /pass.txt

COPY git/ /git

EXPOSE 22

CMD ["./entrypoint.sh"]
