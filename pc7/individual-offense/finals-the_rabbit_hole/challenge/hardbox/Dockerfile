FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
      wabt \
      sudo \
      openssh-server \
      python3 \
      python3-pip \
      python3-venv \
      ca-certificates \
      curl \
      vim nano \
      net-tools \
      curl \
      iputils-ping \
      nmap \
      netcat \
      iproute2 && \
    rm -rf /var/lib/apt/lists/* && \
    pip install flask cryptography requests

RUN useradd -m -s /bin/bash user && \
    usermod -aG sudo user && \
    echo "user ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/user_nopasswd && \
    chmod 0440 /etc/sudoers.d/user_nopasswd

RUN mkdir -p /app
WORKDIR /app

COPY app.py /app/app.py
COPY payload_base.py /app/payload_base.py
COPY run.sh /run.sh
COPY token.txt /home/user/token.txt
COPY challenge_readme.txt /home/user/
COPY README_CHALLENGE.md /home/user/

RUN chown -R user:user /home/user /app && \
    chmod 600 /home/user/token.txt || true

EXPOSE 22 80

ENV hardtoken=TESTTOKEN3

CMD ["/run.sh"]
