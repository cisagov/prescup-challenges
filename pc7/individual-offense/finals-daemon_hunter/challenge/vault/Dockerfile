FROM ubuntu:22.04 AS builder

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y \
      build-essential openssl binutils python3 && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /opt/ctf
COPY vaultd.c ./vaultd.c
COPY build.sh ./build.sh

RUN chmod +x build.sh && ./build.sh

# --- Runtime stage (no source code) ---
FROM ubuntu:22.04

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y \
      openssl python3 netcat && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /opt/ctf
COPY --from=builder /opt/ctf/vaultd ./vaultd
COPY --from=builder /opt/ctf/symbols.txt ./symbols.txt
COPY --from=builder /opt/ctf/secret_parts.h ./secret_parts.h
COPY entrypoint.sh ./entrypoint.sh

RUN chmod +x entrypoint.sh

EXPOSE 1337
ENTRYPOINT ["/opt/ctf/entrypoint.sh"]
CMD ["/opt/ctf/vaultd","1337"]
