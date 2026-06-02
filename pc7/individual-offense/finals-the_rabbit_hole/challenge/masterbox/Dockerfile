FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1

WORKDIR /opt/ctf

COPY . /opt/ctf

RUN set -eux; \
    apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*; \
    # make scripts executable
    chmod +x ./entrypoint.sh || true; \
    chmod +x ./make_secret.py || true; \
    chmod +x ./hardnet.py || true; \
    # create data directory and generate secret if missing
    mkdir -p ./data; \
    python3 make_secret.py ./data/secret.bin || true; \
    # create a default token (operators should replace with their real token after build)
    mkdir -p /root
    #if [ ! -f /root/ultimate_token.txt ]; then echo "CTF{ultra_hard_master_token}" > /root/ultimate_token.txt; chmod 600 /root/ultimate_token.txt; fi; \
    # owner/perm hygiene
    #chown -R root:root /opt/ctf /root/ultimate_token.txt

EXPOSE 42424
ENV mastertoken=TESTTOKEN5

ENTRYPOINT ["./entrypoint.sh"]
