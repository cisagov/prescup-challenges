# Log seeder — one-shot service that waits for Elasticsearch to be ready,
# bulks the Sysmon + PowerShell NDJSON event sets into per-source indices,
# and configures Kibana index patterns. Exits 0 after the seed; the
# compose file pins `restart: "no"`.

FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir \
        requests==2.32.*

WORKDIR /seeder
COPY seed.py            /seeder/seed.py
COPY events/            /seeder/events/

CMD ["python3", "/seeder/seed.py"]
