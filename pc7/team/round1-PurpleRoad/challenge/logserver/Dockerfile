FROM ubuntu:20.04

RUN apt-get update && apt-get install -y vim grep python3 openssh-server curl

COPY logsim.py /logsim.py
RUN useradd -m -s /bin/bash user && echo 'user:password' | chpasswd

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

CMD ["/entrypoint.sh"]
