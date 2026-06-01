FROM python:3.12-slim

RUN apt-get update && apt-get install -y openssl ca-certificates \
  && rm -rf /var/lib/apt/lists/*

WORKDIR /app
RUN pip install --no-cache-dir flask==3.0.3

COPY app.py .

ENV CERT_DIR=/app/certs
CMD ["python", "-m", "flask", "--app", "app", "run", "--host=0.0.0.0", "--port=8080"]
