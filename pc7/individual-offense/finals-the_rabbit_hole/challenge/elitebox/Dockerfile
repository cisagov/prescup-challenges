FROM ubuntu:22.04 AS builder
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y build-essential python3 python3-pip python3-venv gcc clang libssl-dev libffi-dev \
    wget curl make netcat-openbsd python3-flask libpython3-dev pkg-config wabt \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/elitebox

COPY netservice.py wasm_server.py crypto_vault.py suid_helper.c entrypoint.sh  /opt/elitebox/

RUN python3 -m pip install --no-cache-dir cryptography flask

RUN gcc -O2 -fstack-protector-strong -Wl,-z,relro -Wl,-z,now -D_FORTIFY_SOURCE=2 -o /usr/local/bin/suid_helper /opt/elitebox/suid_helper.c \
    && chown root:root /usr/local/bin/suid_helper && chmod 4755 /usr/local/bin/suid_helper


RUN useradd -m player || true && echo "player:player" | chpasswd || true
ENV elitetoken=TESTTOKEN4

RUN mkdir -p /opt/elitebox/data \
    && printf "token{elite_hardbox_placeholder}\n" > /root/ultimate_token.txt \
    && chown root:root /root/ultimate_token.txt && chmod 600 /root/ultimate_token.txt

RUN mkdir -p /opt/elitebox && echo -n "admintoken123" > /opt/elitebox/admin.secret && chmod 600 /opt/elitebox/admin.secret


EXPOSE 31337 8080
ENTRYPOINT ["/opt/elitebox/entrypoint.sh"]
