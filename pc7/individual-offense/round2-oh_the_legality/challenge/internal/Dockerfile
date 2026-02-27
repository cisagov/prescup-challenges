FROM ubuntu:22.04

RUN apt-get update && apt-get install -y tripwire net-tools curl ncat && \
apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y nano dos2unix iproute2 inetutils-ping curl host mtr-tiny tcpdump iptables
COPY setup_tripwire.sh /root/setup_tripwire.sh
COPY tripwire_rules.txt /root/tripwire_rules.txt
RUN chmod +x /root/setup_tripwire.sh && /root/setup_tripwire.sh

COPY app.py /root/app.py
RUN dos2unix /root/app.py

ENTRYPOINT ["python3", "/root/app.py"]
