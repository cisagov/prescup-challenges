FROM alpine:3.19

RUN apk add --no-cache bash netcat-openbsd

COPY healthcheck.sh /usr/local/bin/healthcheck.sh
RUN chmod +x /usr/local/bin/healthcheck.sh

ENTRYPOINT ["/usr/local/bin/healthcheck.sh"]
