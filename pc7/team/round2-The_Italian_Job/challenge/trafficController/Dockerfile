FROM python:3.13.4

RUN apt-get update && apt-get install -y \
    python3 python3-pip iproute2 inetutils-ping \
  && rm -rf /var/lib/apt/lists/*

WORKDIR /app
RUN pip3 install --no-cache-dir flask flask-sock simple-websocket

# App source
COPY app/ /app/

ENTRYPOINT ["python3", "/app/app.py"]