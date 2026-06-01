FROM python:3.12-slim

# ---- system deps ----
RUN apt-get update && apt-get install -y --no-install-recommends \
    tcpdump \
    ca-certificates \
 && rm -rf /var/lib/apt/lists/*

# ---- app user ----
RUN useradd --system --uid 10001 --home /app --shell /usr/sbin/nologin spuser

WORKDIR /app

# ---- code ----
COPY app/ /app/
RUN chmod +x /app/entrypoint.sh

# ---- python deps ----
RUN pip install --no-cache-dir flask gunicorn scapy

# ---- runtime dirs ----
RUN mkdir -p /opt/yard/pcaps /pcaps/ \
 && chown -R spuser:spuser /app /opt/yard

USER spuser

EXPOSE 8080

ENTRYPOINT ["/app/entrypoint.sh"]

