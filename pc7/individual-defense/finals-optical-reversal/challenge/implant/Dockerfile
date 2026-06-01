
FROM ubuntu:24.04

# --- System deps (no build args; tokens will come from runtime env) ---
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y \
    build-essential gdb radare2 python3 python3-pip iproute2 tcpdump curl ca-certificates \
    dnsutils iputils-ping \
    && rm -rf /var/lib/apt/lists/*

# Non-root user
RUN useradd -m -s /bin/bash agent

# --- Mirror shell assets ---
WORKDIR /home/agent
COPY implant/mirror/shsafe /usr/bin/shsafe
COPY implant/mirror/fake_less /usr/bin/less
COPY implant/mirror/profile.d/ /etc/profile.d/
COPY implant/mirror/www/ /opt/www/
RUN chmod +x /usr/bin/shsafe /usr/bin/less

# --- Optic core build ---
WORKDIR /opt/optic
COPY implant/optic-core/Makefile ./Makefile
COPY implant/optic-core/src/ ./src/
RUN mkdir -p bin \
    && make


# --- Service ops tools ---
WORKDIR /opt/tools
COPY implant/service-ops/tools/ ./
RUN make

# --- Implant app (socket + UDP spec + stage4) ---
WORKDIR /opt/implant
COPY implant/app/server.py /opt/implant/server.py
COPY implant/app/optical_link_v1.md /opt/specs/optical_link_v1.md
COPY implant/app/stage4.c /opt/implant/stage4.c
RUN gcc -O2 -fPIC -o /opt/implant/stage4.bin /opt/implant/stage4.c

# Entrypoint script
COPY implant/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh && chown -R agent:agent /opt /home/agent

# Runtime user and environment
USER agent
# ENV LD_PRELOAD=/opt/optic/bin/libldshim.so \
#    IMPLANT_PORT=31337 SPEC_PORT=30415

EXPOSE 31337/tcp 30415/udp 8080/tcp
ENTRYPOINT ["/entrypoint.sh"]