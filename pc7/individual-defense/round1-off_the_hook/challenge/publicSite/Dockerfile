FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

# Install base tools
RUN apt-get update && \
    apt-get install -y \
        sudo \
        cron \
        openssh-server \
        net-tools \
        curl \
        wget \
        iputils-ping \
        vim \
        netcat \
        lsof \
        bash-completion

# Prepare SSH
RUN mkdir -p /var/run/sshd && \
    sed -i 's/^#\?PasswordAuthentication .*/PasswordAuthentication yes/' /etc/ssh/sshd_config

# Create user
RUN useradd -m -s /bin/bash user && \
    echo 'user:password' | chpasswd && \
    usermod -aG sudo user && \
    chown -R user:user /home/user

# End base for this challenge
# Start custom components
RUN apt-get update && apt-get install -y apache2 php libapache2-mod-php

RUN apt-get install -y python3 python3-pip
RUN pip install requests paramiko

RUN apt-get install -y nano
    
COPY web/ /var/www/html/
RUN mkdir /var/www/html/uploads
RUN chown www-data:www-data /var/www/html/uploads

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Start services
ENTRYPOINT [ "/entrypoint.sh" ]
# CMD apache2ctl -D FOREGROUND
