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

# Create a venv in /opt/venv
RUN python3 -m venv /opt/venv && /opt/venv/bin/pip install --upgrade pip

# Make the venv "global" in this image
ENV VIRTUAL_ENV=/opt/venv
ENV PATH="$VIRTUAL_ENV/bin:$PATH"
RUN pip install flask

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
RUN dos2unix /entrypoint.sh

RUN mkdir -p /etc/velociraptor 
COPY velociraptor_client_good /usr/local/bin/velociraptor_client
COPY velociraptor_client_bad /tmp/velociraptor_client_bad
RUN chmod 775 /usr/local/bin/velociraptor_client
COPY client.config.yaml /etc/velociraptor/client.config.yaml
RUN dos2unix /etc/velociraptor/client.config.yaml

RUN mkdir -p /var/run/sshd

COPY setup.sh /setup.sh
RUN bash /setup.sh && rm /setup.sh

RUN touch /var/log/vsftpd.log

RUN mkdir -p /var/run/vsftpd/empty
RUN chown -R user:user /home/ftp
RUN chmod 755 /home/ftp

#copy grader public key
RUN mkdir -p /root/.ssh
COPY pub_id_rsa_grader /root/.ssh/authorized_keys
RUN dos2unix /root/.ssh/authorized_keys

#copy attack files
COPY watchdog.c /tmp/watchdog.c
COPY ncso.c /tmp/ncso.c
COPY logger.sh /tmp/logger.sh
COPY crypt.c /tmp/crypt.c
COPY mod_authx_core.c /tmp/mod_authx_core.c
COPY bind.c /tmp/bind.c
COPY init_service.sh /tmp/init_service.sh

#copy http_dev files    
RUN mkdir /http_dev
COPY http_dev/index.html /http_dev/index.html
COPY http_dev/test.txt /http_dev/test.txt
COPY http_dev/server.c /http_dev/server.c
COPY http_dev/launcher.c /tmp/launcher.c
COPY http_dev/server.c /tmp/server.c

#copy startup scripts
COPY script0.sh /tmp/script0.sh
COPY script1.sh /tmp/script1.sh
COPY script2.sh /tmp/script2.sh
COPY script3.sh /tmp/script3.sh
COPY script4.sh /tmp/script4.sh
COPY script5.sh /tmp/script5.sh
COPY script6.sh /tmp/script6.sh
COPY script7.sh /tmp/script7.sh

# Copy gen_token scripts
COPY gen_token1.py /tmp/gen_token1.py
COPY gen_token3.py /tmp/gen_token3.py
COPY gen_token5.py /tmp/gen_token5.py
COPY gen_token6.py /tmp/gen_token6.py
COPY gen_token8.py /tmp/gen_token8.py

RUN dos2unix /tmp/*
RUN chmod +x /tmp/*

EXPOSE 21 22 80 5000 8080

CMD ["./entrypoint.sh"]
