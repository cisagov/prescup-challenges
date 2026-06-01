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
    dnsutils \
    nmap \
    vim \
    nano \
    python3 \
    dos2unix \
    telnet \
    tcpdump \
    expect \
    tmux \
    openssh-server && \
    useradd -m -s /bin/bash user && echo 'user:password' | chpasswd

RUN adduser user sudo
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

COPY connect.sh /connect.sh
RUN chmod +x /connect.sh

COPY grade.sh /grade.sh
RUN chmod +x /grade.sh
RUN dos2unix /grade.sh

COPY id_rsa /root/.ssh/id_rsa
RUN chmod 600 /root/.ssh/id_rsa
RUN dos2unix /root/.ssh/id_rsa
COPY pub_id_rsa /root/.ssh/id_rsa.pub
RUN chmod 600 /root/.ssh/id_rsa.pub
RUN dos2unix /root/.ssh/id_rsa.pub
COPY pub_id_rsa_grader /root/.ssh/authorized_keys
RUN dos2unix /root/.ssh/authorized_keys

RUN mkdir -p /var/run/sshd

EXPOSE 22

CMD ["./entrypoint.sh"]
