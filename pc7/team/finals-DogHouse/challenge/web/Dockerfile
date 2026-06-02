FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    openssh-server \
    dos2unix \
 && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /var/run/sshd
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY templates/ ./templates/
COPY app.py .
COPY upload_script.sh .
RUN dos2unix ./app.py ./upload_script.sh
RUN chmod +x ./upload_script.sh

COPY id_rsa /root/.ssh/id_rsa
RUN chmod 600 /root/.ssh/id_rsa
RUN dos2unix /root/.ssh/id_rsa

COPY pub_id_rsa /root/.ssh/id_rsa.pub
RUN dos2unix /root/.ssh/id_rsa.pub

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

COPY pub_id_rsa /root/.ssh/authorized_keys
RUN dos2unix /root/.ssh/authorized_keys

RUN mkdir -p /app/uploads && chown -R root:root /app/uploads

EXPOSE 80

ENTRYPOINT ["/entrypoint.sh"]
