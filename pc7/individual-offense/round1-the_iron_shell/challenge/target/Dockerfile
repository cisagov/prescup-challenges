FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

# 1) Install all needed packages
RUN apt update
RUN apt install -y \
    python3-pip \
    inetutils-ping \
    openssh-server \
    john \
    inotify-tools \
    ssh \
    curl \
    libcap2-bin \
    authbind \
    sudo \
    openssh-client \
    dos2unix \
    cron \
  && rm -rf /var/lib/apt/lists/*

# 2) Create the CTF user and backup keydir (Task 2 setup)
RUN useradd -m -s /bin/bash user ; echo "user:bubbles" | chpasswd\
 && mkdir -p /home/user/.ssh 
COPY sshKeys/ /home/user/.ssh/
RUN dos2unix /home/user/.ssh/id_rsa
RUN dos2unix /home/user/.ssh/id_rsa.pub
RUN chown -R user:user /home/user/.ssh 
# RUN chmod 755 /home/user/.ssh

# 3) Authorize user’s public key for SSH login
#RUN mkdir -p /home/user/.ssh \
RUN cat /home/user/.ssh/id_rsa.pub > /home/user/.ssh/authorized_keys \
 && chown -R user:user /home/user/.ssh \
 && chmod 600 /home/user/.ssh/id_rsa \
 && chmod 611 /home/user/.ssh/id_rsa.pub \
 && chmod 600 /home/user/.ssh/authorized_keys 
 # OpenSSH prep
RUN mkdir /var/run/sshd \
 && sed -i 's/#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config \
 && sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin no/' /etc/ssh/sshd_config

# 4) Install Flask and copy in the vulnerable app (Task 1 setup)
RUN pip3 install flask
COPY devportal.py /opt/devportal.py

# 5) Install the SUID root shell (Task 3 setup)
RUN cp /bin/bash /usr/local/bin/rootme \
 && chmod +s /usr/local/bin/rootme

# 6) Create the secret flag and enable auditing (Task 4 setup)
RUN mkdir -p /opt/secret 
COPY flag.c /opt/secret/flag.c

# 7) Copy in entrypoint script
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 22 8000

ENTRYPOINT ["/entrypoint.sh"]
