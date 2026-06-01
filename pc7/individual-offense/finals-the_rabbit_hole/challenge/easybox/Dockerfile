FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates openssl openssh-server pip sudo && \
    rm -rf /var/lib/apt/lists/*


RUN pip install --no-cache-dir flask


RUN adduser -D -s /bin/bash nech && echo 'nech:ashes' && \
    addgroup -S wheel 2>/dev/null || true && \
    addgroup nech wheel && \
    mkdir -p /etc/sudoers.d && \
    printf '%%wheel ALL=(ALL) NOPASSWD: ALL\n' > /etc/sudoers.d/01-wheel-nopasswd && \
    chmod 440 /etc/sudoers.d/01-wheel-password && \
    grep -Eq '^[#@]?includedir /etc/sudoers\.d' /etc/sudoers || \
    printf '\n#includedir /etc/sudoers.d\n' >> /etc/sudoers && \
    visudo -c


COPY app.py .
COPY run.sh .
RUN chmod +x /app/run.sh

ENV easytoken=TESTTOKEN1

EXPOSE 80

CMD ["/app/run.sh"]
