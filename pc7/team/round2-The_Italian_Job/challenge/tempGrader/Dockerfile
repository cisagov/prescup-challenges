FROM python:3.13.4

RUN apt-get update && apt-get install -y \
    python3 python3-pip iproute2 inetutils-ping ssh \
  && rm -rf /var/lib/apt/lists/*

WORKDIR /app
RUN pip3 install --no-cache-dir flask paramiko requests

# App source
COPY app.py Heist.png /app/
COPY grader_key /app/
RUN chmod 600 /app/grader_key
COPY grader_key.pub /app/
# COPY entrypoint.sh /
# RUN chmod +x /entrypoint.sh

# ENTRYPOINT ["/entrypoint.sh"]
CMD ["python3", "/app/app.py"]