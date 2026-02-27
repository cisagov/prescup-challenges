FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1

# Base deps
RUN apt-get update && apt-get install -y \
    curl ca-certificates perl make gcc \
    python3 python3-pip sqlite3 inotify-tools strace supervisor iproute2 unzip openssh-server jq inetutils-ping netcat nmap \
  && rm -rf /var/lib/apt/lists/*

# Python deps
RUN pip3 install --no-cache-dir watchdog


RUN mkdir -p /root/.ssh
RUN mkdir -p /var/run/sshd 
COPY grader_key.pub /root/.ssh/authorized_keys
RUN chmod 700 /root/.ssh \
 && chmod 600 /root/.ssh/authorized_keys \
 && chown -R root:root /root/.ssh
RUN sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
RUN sed -i 's/^#?PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config
RUN ssh-keygen -A

# Copy app files
WORKDIR /app
COPY updater.py ./

COPY entrypoint.sh /
RUN chmod +x /entrypoint.sh
COPY supervisord.conf /etc/supervisord.conf
ENTRYPOINT ["/entrypoint.sh"]
# CMD ["/usr/bin/supervisord", "-c", "/etc/supervisord.conf"]