FROM ubuntu:20.04

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y \
    vsftpd \
    iptables \
    fail2ban \
    gcc \
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
    openssh-server gdb ltrace && \
    useradd -m purple && echo 'purple:purple' | chpasswd

# Setup FTP
COPY setup.sh /setup.sh
RUN bash /setup.sh && rm /setup.sh

# Setup token
COPY token.txt /home/purple/token.txt
RUN chown purple:purple /home/purple/token.txt && chmod 666 /home/purple/token.txt

RUN touch /var/log/vsfptd.log
#setup users
RUN useradd -m grader -s /bin/bash && mkdir /home/grader/.ssh && usermod -aG sudo grader && echo "grader ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers
COPY grader_id_rsa /home/grader/.ssh/id_rsa
COPY grader_id_rsa_pub /home/grader/.ssh/id_rsa.pub
RUN dos2unix /home/grader/.ssh/*
RUN cat /home/grader/.ssh/id_rsa.pub > /home/grader/.ssh/authorized_keys \
    && chown -R grader:grader /home/grader/.ssh \
    && chmod 600 /home/grader/.ssh/id_rsa \
    && chmod 611 /home/grader/.ssh/id_rsa.pub \
    && chmod 600 /home/grader/.ssh/authorized_keys 


RUN useradd -m user -s /bin/bash && echo 'user:superpass' | chpasswd && usermod -aG sudo user

# Setup logging
RUN touch /var/log/fake_auth.log && chmod 666 /var/log/fake_auth.log

# Fail2ban configuration
COPY fail2ban_config/jail.local /etc/fail2ban/jail.local

# Create secure chroot dir
RUN mkdir -p /var/run/vsftpd/empty\
# Create anon_root dir and permissions
    && mkdir -p /home/purple/ftp\
    && chown -R nobody:nogroup /home/purple/ftp\
    && chmod 755 /home/purple/ftp/ \
    && mkdir -p /home/purple/ftp/token \
    && cp /home/purple/token.txt /home/purple/ftp/token/

COPY entrypoint.sh /entrypoint.sh
RUN dos2unix /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 21 20 22


CMD ["/entrypoint.sh"]
