FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# OS deps: OpenSSL libs + curl for simple debugging if needed
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates openssl curl && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Python deps
RUN pip install --no-cache-dir flask cryptography requests pyOpenSSL cbor2

# App
COPY app.py /app/app.py

EXPOSE 80
CMD ["python", "/app/app.py"]
