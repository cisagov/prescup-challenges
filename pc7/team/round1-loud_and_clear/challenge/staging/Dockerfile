FROM debian:stable-slim

ENV DEBIAN_FRONTEND=noninteractive

# Base packages (exim4 + python for challenge services)
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      exim4 \
      python3 \
      ca-certificates \
      bash \
      tini \
 && rm -rf /var/lib/apt/lists/*

# Challenge directories + Exim runtime directories
# NOTE: Debian-exim user/group are created by the exim4 package install above.
RUN set -eux; \
    mkdir -p \
      /opt/lancer/bin \
      /opt/lancer/state \
      /opt/lancer/tokens \
      /var/log/exim4 \
      /var/spool/exim4 \
      /var/spool/exim4/input \
      /var/spool/exim4/msglog; \
    touch /var/log/exim4/mainlog /var/log/exim4/rejectlog /var/log/exim4/paniclog; \
    chown -R Debian-exim:Debian-exim /var/spool/exim4; \
    chown -R Debian-exim:adm /var/log/exim4 || true; \
    \
    # Critical for platforms that run the container as a random unprivileged UID/GID:
    # - 0755 allows Exim/readfile to traverse /opt/lancer/state
    # - 1777 allows plant@ to stage payloads without needing a specific uid/gid
    chmod 0755 /opt /opt/lancer; \
    chmod 1777 /opt/lancer/state; \
    chmod 0750 /opt/lancer/tokens

# Exim config (ensure it contains: daemon_smtp_ports = 2525)
COPY exim.conf /etc/exim4/exim.conf

# Challenge services + hooks
COPY patchd.py /opt/lancer/bin/patchd.py
COPY qa_hook.py /opt/lancer/bin/qa_hook.py
COPY entrypoint.sh /entrypoint.sh

RUN chmod +x /entrypoint.sh \
 && chmod +x /opt/lancer/bin/patchd.py /opt/lancer/bin/qa_hook.py 

EXPOSE 2525 31337

ENTRYPOINT ["/usr/bin/tini","--"]
CMD ["/entrypoint.sh"]

