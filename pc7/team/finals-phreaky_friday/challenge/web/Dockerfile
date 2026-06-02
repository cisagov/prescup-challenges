# syntax=docker/dockerfile:1
FROM debian:bullseye as genbase
WORKDIR /gen
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 python3-pip libsndfile1 fonts-dejavu-core ca-certificates && \
    rm -rf /var/lib/apt/lists/*
COPY generator/requirements.txt .
RUN pip3 install --no-cache-dir -r requirements.txt
COPY generator/ ./

FROM nginx:stable
WORKDIR /app
RUN apt-get update && apt-get install -y python3 python3-pip
RUN pip3 install --no-cache-dir numpy soundfile scapy pycryptodome  Pillow --break-system-packages
COPY site/ /usr/share/nginx/html/
COPY site/PF-Specs.md /usr/share/nginx/html/
COPY site/mission_briefing.txt /usr/share/nginx/html/
RUN chmod 666 /usr/share/nginx/html/PF-Specs.md
RUN chmod 666 /usr/share/nginx/html/mission_briefing.txt
COPY --from=genbase /gen /app/generator
COPY web/nginx.conf /etc/nginx/nginx.conf
# COPY web/default.conf /etc/nginx/conf.d/default.conf
COPY web/entrypoint.sh entrypoint.sh
RUN chmod +x /app/entrypoint.sh
EXPOSE 80
ENTRYPOINT ["/app/entrypoint.sh"]
