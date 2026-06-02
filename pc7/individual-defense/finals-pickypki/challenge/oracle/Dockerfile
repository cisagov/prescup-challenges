# hpke_oracle/Dockerfile
FROM python:3.12-alpine

RUN apk add --no-cache gcc musl-dev libffi-dev openssl-dev
RUN pip install --no-cache-dir flask cryptography

WORKDIR /app
COPY app.py /app/app.py
COPY entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

EXPOSE 8081
CMD ["/app/entrypoint.sh"]
