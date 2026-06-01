FROM python:3.12-slim

WORKDIR /app

RUN apt-get update && \
    apt-get install -y --no-install-recommends openssl curl && \
    rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir Flask==3.0.3 gunicorn==22.0.0 PyJWT==2.9.0 cryptography==43.0.1 requests==2.32.3


COPY ./app /app
COPY entrypoint.sh .
RUN chmod +x /app/entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]
