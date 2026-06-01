FROM python:latest

RUN pip install --upgrade pip
RUN pip install requests pythonping PyYAML flask flask-executor
RUN apt update && apt install -y iproute2 iputils-ping libc-bin dnsutils nmap

# For CoreDNS
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates wget jq

RUN wget -q https://github.com/coredns/coredns/releases/download/v1.14.1/coredns_1.14.1_linux_amd64.tgz -O coredns_amd64.tgz \
    && tar -xzf coredns_amd64.tgz \
    && mv coredns /usr/local/bin/ \
    && chmod +x /usr/local/bin/coredns \
    && rm coredns_amd64.tgz

RUN mkdir /app/ /custom_scripts/ /hosted_files/
WORKDIR /app

COPY ./src .
COPY ./wallpapers /app/wallpapers
COPY ./grader_config.yml /config.yml

RUN mkdir -p /app/dns
COPY dns/ /app/dns
RUN chmod +x /app/dns/genzones.py

ENV CHALLENGE_PORT="80"

RUN echo '#!/usr/bin/env python3\n# This is just a no op, in case you dont need any start up\npass' > /custom_scripts/empty.py
RUN chmod +x /custom_scripts/empty.py

COPY entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]