FROM python:3.12-slim

WORKDIR /app

RUN apt-get update && \
apt-get install -y --no-install-recommends openssl curl && \
rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir Flask==3.0.3 Authlib==1.3.2 PyJWT==2.9.0 Flask-SQLAlchemy==3.1.1 gunicorn==22.0.0

COPY app.py .
COPY entrypoint.sh mint_cert.py ./
RUN chmod +x /app/entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]
