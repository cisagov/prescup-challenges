FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates openssl && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Python deps
RUN pip install --no-cache-dir flask cryptography cbor2 pyOpenSSL requests

# Init script creates an unencrypted RSA CA key & self-signed CA cert
COPY ca_init.sh /usr/local/bin/ca_init.sh
RUN chmod +x /usr/local/bin/ca_init.sh

# CA service
COPY app.py /app/app.py

EXPOSE 80

CMD ["/bin/sh", "-c", "/usr/local/bin/ca_init.sh && python /app/app.py"]
