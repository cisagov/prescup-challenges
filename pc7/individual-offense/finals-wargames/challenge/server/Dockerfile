# Got this from chatgpt for building against a specific version of glibc... Let's give it a shot!
# Rebuildable, version-pinned glibc toolchain container for your pthread internals work.
# It clones a specific GitHub ref of glibc, builds it into /opt/glibc,
# and provides helper wrappers to compile/run binaries against that exact glibc.

FROM debian:stable-slim

ARG DEBIAN_FRONTEND=noninteractive

# --- build deps for glibc -----------------------------------------------------
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential git gawk bison python3 texinfo gperf \
    linux-libc-dev file ca-certificates pkg-config \
    locales wget xinetd supervisor dpkg-dev nginx 

# Minimal locale used by some glibc bits/tools
RUN localedef -i C -f UTF-8 C.UTF-8 || true
ENV LANG=C.UTF-8 LC_ALL=C.UTF-8

# --- choose the glibc repo/ref here ------------------------------------------
# You can override these at build time:
#   docker build --build-arg GLIBC_REPO=https://github.com/bminor/glibc \
#                --build-arg GLIBC_REF=glibc-2.39 \
#                -t glibc-pthread-lab .
ARG GLIBC_REPO="https://github.com/bminor/glibc.git"
ARG GLIBC_REF="glibc-2.39"

# --- fetch glibc at the exact ref (tag or commit) -----------------------------
WORKDIR /src
RUN git clone "$GLIBC_REPO" glibc && cd glibc \
 && git fetch --all --tags \
 && git checkout --detach "$GLIBC_REF"

# ensure /usr/include/asm resolves to the arch UAPI headers (no CPPFLAGS hacks!)
RUN set -e; MA="$(dpkg-architecture -qDEB_HOST_MULTIARCH)"; \
    ln -sf "/usr/include/${MA}/asm" /usr/include/asm

# --- build & install glibc into /opt/glibc -----------------------------------
# out-of-tree build + correct header paths
WORKDIR /build/glibc
RUN /src/glibc/configure \
      --prefix=/opt/glibc \
      --disable-werror \
      --with-headers=/usr/include \
      libc_cv_slibdir=/opt/glibc/lib \
 && make -j"$(nproc)" \
 && make install

# --- helpers to compile/run against pinned glibc ------------------------------
# On x86_64 GNU, the dynamic linker is ld-linux-x86-64.so.2. Adjust for other arches.
ENV GLIBC_PREFIX=/opt/glibc
ENV GLIBC_LD_SO=/opt/glibc/lib/ld-linux-x86-64.so.2
ENV GLIBC_LIB=/opt/glibc/lib
ENV GLIBC_INC=/opt/glibc/include

# Wrapper compiler that prefers the pinned glibc at link time and sets rpath.
# Usage: glibc-gcc your.c -pthread -o yourbin
RUN printf '#!/usr/bin/env bash\n'                                   >  /usr/local/bin/glibc-gcc \
 && printf 'set -euo pipefail\n'                                     >> /usr/local/bin/glibc-gcc \
 && printf 'exec gcc -I"%s" -L"%s" "$@" \\\n' "$GLIBC_INC" "$GLIBC_LIB" >> /usr/local/bin/glibc-gcc \
 && printf '  -Wl,--dynamic-linker="%s" \\\n' "$GLIBC_LD_SO"         >> /usr/local/bin/glibc-gcc \
 && printf '  -Wl,-rpath="%s" -Wl,-rpath-link="%s"\n' "$GLIBC_LIB" "$GLIBC_LIB" >> /usr/local/bin/glibc-gcc \
 && chmod +x /usr/local/bin/glibc-gcc

### End libc stuff

WORKDIR /app

# Just random data for clearance_codes!
RUN mkdir -p /devices \
 && ln -s /dev/urandom /devices/clearance_codes

RUN chmod 555 /devices/clearance_codes

# Configs for xinetd and supervisord
COPY ./conf/xinetd.conf /etc/xinetd.conf
COPY ./conf/supervisord.conf /etc/supervisor/supervisord.conf

# Copy over code  and build
COPY app/ /app/
RUN glibc-gcc -s main.c -pthread -o /app/demo

COPY ./entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh /app/run_demo.sh

# nginx setup
RUN mkdir -p /var/www
RUN cp /app/demo /opt/glibc/lib/ld-linux-x86-64.so.2 /opt/glibc/lib/libc.so.6 /var/www/
RUN rm -r /var/www/html
COPY ./conf/nginx.conf /etc/nginx/nginx.conf

# Patch nginx logging to go to stdout/stderr for Supervisor + Docker
RUN sed -i 's|access_log .*|access_log /dev/stdout;|' /etc/nginx/sites-available/default && \
    sed -i 's|error_log .*|error_log /dev/stderr warn;|' /etc/nginx/sites-available/default

RUN printf "%s\n" \
    "server {" \
    "    listen 80;" \
    "    root /var/www;" \
    "    autoindex on;" \
    "}" > /etc/nginx/sites-available/default

# Logging pipe for the running binary
RUN mkfifo /tmp/demo_logs && chmod 666 /tmp/demo_logs

# Create and set permissions for token files
RUN touch /app/functionToken.txt /app/systemToken.txt /app/leakToken.txt
RUN chmod 644 /app/functionToken.txt /app/systemToken.txt /app/leakToken.txt

ENTRYPOINT [ "/entrypoint.sh" ]