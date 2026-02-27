FROM ubuntu:22.04

WORKDIR /logger

COPY collector.py ./
COPY entrypoint.sh /


RUN apt update && DEBIAN_FRONTEND=noninteractive apt install -y tcpdump ssh sudo openssh-server python3 pip
RUN pip install flask
RUN useradd -m -s /usr/bin/bash user ; echo "user:password" | chpasswd ; usermod -aG sudo user
RUN chmod +x /entrypoint.sh

EXPOSE 9000

CMD ["/entrypoint.sh"]
