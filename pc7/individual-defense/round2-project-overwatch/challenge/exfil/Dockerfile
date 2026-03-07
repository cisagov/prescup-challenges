FROM python:3.12-slim

# Minimal runtime deps
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates tzdata && rm -rf /var/lib/apt/lists/*

# Create loot dir
RUN mkdir -p /opt/loot

# Copy script
COPY exfil_dns.py /usr/local/bin/exfil_dns.py
RUN chmod 755 /usr/local/bin/exfil_dns.py

ENTRYPOINT ["/usr/local/bin/exfil_dns.py"]