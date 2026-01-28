FROM python:3.13.4-slim

# Install necessary networking tools
RUN apt-get update && apt-get install -y iproute2 iputils-ping net-tools

RUN apt update && apt install -y dnsutils tcpdump

RUN pip install dnspython

COPY victim.py /victim.py

CMD ["python", "/victim.py"]
