FROM nginx:alpine

# Tools (including openssh server & sudo)
RUN apk add --no-cache \
      openssl ca-certificates openssh sudo bash python3 py3-pip \
      vim nano curl jq gcc musl-dev libffi-dev openssl-dev rust cargo

# Python venv (optional, as you had)
RUN python3 -m venv /opt/web-venv && \
    . /opt/web-venv/bin/activate && \
    pip install --upgrade pip && \
    pip install cryptography cbor2 requests

# User + wheel sudo without password
RUN adduser -D -s /bin/bash user && \
    echo 'user:password' | chpasswd && \
    addgroup -S wheel || true && \
    addgroup user wheel && \
    mkdir -p /etc/sudoers.d && \
    printf '%%wheel ALL=(ALL) NOPASSWD: ALL\n' > /etc/sudoers.d/01-wheel-nopasswd && \
    chmod 440 /etc/sudoers.d/01-wheel-nopasswd && \
    grep -Eq '^[#@]?includedir /etc/sudoers\.d' /etc/sudoers || \
      printf '\n#includedir /etc/sudoers.d\n' >> /etc/sudoers && \
    visudo -c

# Relax/ensure password auth for SSH (optional but explicit)
# Alpine's default usually allows password auth, but let's be explicit:
RUN sed -ri 's/^\s*#?\s*PasswordAuthentication\s+.*/PasswordAuthentication yes/g' /etc/ssh/sshd_config && \
    sed -ri 's/^\s*#?\s*UsePAM\s+.*/UsePAM no/g' /etc/ssh/sshd_config

ENV CERT_DIR=/etc/nginx/certs \
    LIVE_DIR=/runtime-certs

RUN mkdir -p "$CERT_DIR" "$LIVE_DIR"

# Default TLS vhost
COPY default.conf /etc/nginx/conf.d/default.conf
COPY nginx.conf /etc/nginx/nginx.conf

# Startup script
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 443 22
CMD ["/entrypoint.sh"]
