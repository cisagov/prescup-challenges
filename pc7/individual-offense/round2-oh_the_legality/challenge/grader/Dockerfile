FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt
RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y iproute2 inetutils-ping curl host mtr-tiny tcpdump iptables
COPY app.py .
COPY entrypoint.sh .
RUN chmod +x entrypoint.sh

ENV token3="TestToken3"
EXPOSE 80

CMD ["bash", "entrypoint.sh"]
