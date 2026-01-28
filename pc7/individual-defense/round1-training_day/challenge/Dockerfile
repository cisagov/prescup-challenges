# ── final stage ────────────────────────────────
FROM debian:bullseye 
ENV DEBIAN_FRONTEND=noninteractive

RUN mkdir /challenge
WORKDIR /challenge
COPY scripts/. /challenge/

RUN apt update -y && apt -y install bash apache2 \
    sudo \
    coreutils \
    net-tools \
    apache2 \
    iputils-ping \
    netcat-traditional \
    genext2fs \
    sleuthkit \
    binwalk \
    foremost \
    socat \
    bash \
    python3 \
    pkg-config \
    libssl-dev \
    python3-pip \
    nmap \
    && ln -s /usr/bin/python3 /usr/bin/python \
    && pip3 install scapy 

RUN chmod +x /challenge/entrypoint.sh 

# Configure web server

WORKDIR /var/www/html/

COPY index.html .
RUN chmod +x index.html

EXPOSE 80

ENTRYPOINT ["/bin/bash", "/challenge/entrypoint.sh"]

