# Backup and replace
FROM python:3.12-slim

USER root

RUN apt-get update && apt-get install -y --no-install-recommends \
    openssl python3-pip bash ca-certificates curl jq coreutils tar xxd \
 && pip install fastapi uvicorn[standard] \
 && rm -rf /var/lib/apt/lists/*

RUN groupadd -g 1000 appuser

# Create new user
RUN useradd -m -s /bin/bash -u 1001 -g appuser appuser 

RUN set -eu

# Create structure
COPY pki /opt/embassy-pki
RUN mkdir -p /app/data /tmp
COPY app/ /app
COPY entrypoint.sh /app/
RUN chown -R appuser:appuser /app/ /tmp/
RUN sed -i 's/\r$//' /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

# Non-root runtime & writable dirs (works with read_only: true in compose)
EXPOSE 8080

# Run via sh so the shell *reads* the script (works even if /app is noexec)
ENTRYPOINT ["/bin/bash", "/app/entrypoint.sh"]

