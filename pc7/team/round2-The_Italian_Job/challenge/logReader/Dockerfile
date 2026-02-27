FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1

# Base deps
RUN apt-get update && apt-get install -y \
    curl ca-certificates perl make gcc \
    python3 python3-pip sqlite3 inotify-tools strace supervisor iproute2 unzip openssh-server inetutils-ping netcat nmap \
  && rm -rf /var/lib/apt/lists/*

# Vulnerable ExifTool (<=12.23). Using 12.20.
WORKDIR /tmp/exif
COPY exiftool-12.20.tar.gz ./

# 2) Extract the archive
RUN tar -xzf exiftool-12.20.tar.gz

WORKDIR /tmp/exif/exiftool-12.20

# 3) Install using Perl's standard build process
RUN perl Makefile.PL
RUN make
RUN make install
RUN rm -r /tmp/*

# Python deps
RUN pip3 install --no-cache-dir watchdog

# App layout and unprivileged user
RUN useradd -m -u 1000 user
RUN mkdir -p /app /mnt/usb/DCIM /mnt/usb/logs /var/lib/tmc /var/log && \
    chown -R user:user /app /mnt/usb /var/lib/tmc /var/log

# Copy app files
# COPY entrypoint.sh /app/entrypoint.sh
COPY ingest.py /app/ingest.py
# RUN chmod +x /app/entrypoint.sh
COPY supervisord.conf /etc/supervisord.conf

COPY entrypoint.sh /
RUN chmod +x /entrypoint.sh

RUN mkdir -p /home/user/.ssh
RUN chown user:user /home/user/.ssh
RUN mkdir -p /var/run/sshd 
COPY grader_key.pub /home/user/.ssh/authorized_keys
RUN sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config

RUN chmod 700 /home/user/.ssh \
 && chmod 600 /home/user/.ssh/authorized_keys \
 && chown -R user:user /home/user/.ssh
RUN ssh-keygen -A

# USER user  # Start as root and drop to user with supervisord
WORKDIR /app

ENTRYPOINT [ "/entrypoint.sh" ]
# CMD ["/usr/bin/supervisord", "-c", "/etc/supervisord.conf"]