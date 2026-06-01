# challenge/diag/Dockerfile
FROM python:3.12-slim
RUN apt-get update && apt-get install -y curl jq iproute2 bash && rm -rf /var/lib/apt/lists/*
WORKDIR /opt/diag
COPY health.sh /opt/diag/health.sh
COPY health.py /opt/diag/health.py
RUN chmod +x /opt/diag/health.sh
ENTRYPOINT ["/bin/bash", "/opt/diag/health.sh"]

