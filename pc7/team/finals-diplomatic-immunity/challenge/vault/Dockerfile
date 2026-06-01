FROM python:3.12-slim

USER root

RUN apt-get update && apt-get install -y --no-install-recommends openssl bash ca-certificates \
 && pip install --no-cache-dir fastapi uvicorn[standard] \
 && rm -rf /var/lib/apt/lists/*

# Bake self-signed CA and server certs during build (adjust CNs as needed)
RUN mkdir -p /etc/ssl/api-vault /etc/ssl/api-vault/ca && \
    openssl req -x509 -newkey rsa:2048 -days 365 -nodes \
      -keyout /etc/ssl/api-vault/ca/ca.key \
      -out    /etc/ssl/api-vault/ca/ca.crt.pem \
      -subj "/CN=Embassy CA" && \
    openssl genrsa -out /etc/ssl/api-vault/server.key 2048 && \
    openssl req -new -key /etc/ssl/api-vault/server.key \
      -out /etc/ssl/api-vault/server.csr \
      -subj "/CN=api-vault.embassy.svc" && \
    openssl x509 -req \
      -in /etc/ssl/api-vault/server.csr \
      -CA /etc/ssl/api-vault/ca/ca.crt.pem \
      -CAkey /etc/ssl/api-vault/ca/ca.key \
      -CAcreateserial \
      -out /etc/ssl/api-vault/server.crt \
      -days 365 && \
    chmod 0444 /etc/ssl/api-vault/server.crt && \
    chmod 0400 /etc/ssl/api-vault/server.key

RUN groupadd -g 1000 appuser

# Create new user
RUN useradd -m -s /bin/bash -u 1001 -g appuser appuser 

RUN set -eu

# Create structure
COPY pki /opt/embassy-pki
RUN mkdir -p /app/ /ca/
COPY app/ /app
# COPY ca/ca.crt.pem /ca/
# COPY ca/ca.key /ca/
COPY entrypoint.sh /app/
RUN chown -R appuser:appuser /app/ /ca/
RUN sed -i 's/\r$//' /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh


ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1

EXPOSE 8443

USER root

# Run via sh so the shell *reads* the script (works even if /app is noexec)
ENTRYPOINT ["/bin/bash", "/app/entrypoint.sh"]

