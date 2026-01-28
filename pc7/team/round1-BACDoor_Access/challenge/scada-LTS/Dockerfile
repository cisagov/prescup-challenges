FROM scadalts/scadalts:v2.7.8.1

RUN apt update && apt install -y iputils-ping tcpdump iproute2 python3

COPY entrypoint.sh /entrypoint.sh
COPY export.zip ip_replacement.py resolver_client.py /
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
