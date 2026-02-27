FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1

# Base deps
RUN apt-get update && apt-get install -y \
    curl ca-certificates perl make gcc \
    python3 python3-pip sqlite3 inotify-tools strace supervisor iproute2 unzip openssh-server sudo inetutils-ping netcat nmap \
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
RUN useradd -m -s /bin/bash user && \
    echo 'user:password' | chpasswd && \
    adduser user sudo
RUN mkdir -p /app /mnt/usb/DCIM /mnt/usb/logs /var/lib/tmc /var/log && \
    chown -R user:user /app /mnt/usb /var/lib/tmc /var/log
RUN mkdir -p /var/run/sshd

# Copy app files
COPY ingest.py /app/ingest.py
COPY supervisord.conf /etc/supervisord.conf

COPY imgs/ /mnt/usb/DCIM/
COPY logs/ /mnt/usb/logs/

WORKDIR /app

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
ENTRYPOINT [ "/entrypoint.sh" ]
# CMD ["/usr/bin/supervisord", "-c", "/etc/supervisord.conf"]