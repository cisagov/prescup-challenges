FROM ubuntu:20.04
RUN apt-get update && \
    apt-get install -y postfix python3 libssl-dev gcc && \
    rm -rf /var/lib/apt/lists/*

ENV token4=""

# Place the dummy payload file
RUN mkdir /payload
RUN mkdir /payloadsrc
COPY flag.c /payloadsrc/payload.c


# Postfix config + forward‐all transport
COPY main.cf    /etc/postfix/main.cf
COPY transport  /etc/postfix/transport
RUN postmap /etc/postfix/transport

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh



EXPOSE 80
CMD ["/entrypoint.sh"]