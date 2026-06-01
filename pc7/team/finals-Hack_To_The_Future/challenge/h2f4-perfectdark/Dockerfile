FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    openssh-server \
    vim \
    nano \
    less \
    net-tools \
    iproute2 \
    tcpdump \
    gdb \
    gcc \
    make \
    python3 \
    python3-pip \
    strace \
    lsof \
    procps \
    file \
    curl \
    wget \
    xxd \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Create analysis user
RUN useradd -m -s /bin/bash "jack.dark" && \
    echo "jack.dark:password" | chpasswd

# SSHD configuration
RUN mkdir -p /var/run/sshd
COPY sshd_config /etc/ssh/sshd_config

# MOTD
COPY motd /etc/motd

# Visible challenge surface
WORKDIR /opt/farsight
COPY entrypoint.sh /entrypoint.sh
COPY lattice_decode.c /opt/farsight/lattice_decode.c
COPY relic_fragment.txt /opt/farsight/relic_fragment.txt
COPY opticbin/ /opt/optic/

# Hidden runtime assets
RUN mkdir -p /usr/local/lib/.fs_boot
COPY hidden/farsight_init.sh /usr/local/lib/.fs_boot/farsight_init.sh
COPY hidden/farsightd.py /usr/local/lib/.fs_boot/farsightd.py
COPY hidden/daybreak_relay.py /usr/local/lib/.fs_boot/daybreak_relay.py
COPY hidden/reveal_manager.py /usr/local/lib/.fs_boot/reveal_manager.py
COPY hidden/farsight_ctl.c /tmp/farsight_ctl.c
COPY hidden/farsight_destroy.c /tmp/farsight_destroy.c

# Build hidden privileged binaries
RUN gcc /tmp/farsight_ctl.c -O2 -s -Wall -Wextra -o /usr/local/lib/.fs_boot/farsight_ctl.bin && \
    gcc /tmp/farsight_destroy.c -O2 -s -Wall -Wextra -o /usr/local/lib/.fs_boot/farsight_destroy.bin && \
    rm -f /tmp/farsight_ctl.c /tmp/farsight_destroy.c

# Permissions
RUN chmod 0755 /entrypoint.sh && \
    chmod 0755 /opt/optic/* && \
    chmod 0644 /opt/farsight/lattice_decode.c /opt/farsight/relic_fragment.txt && \
    chown -R root:root /usr/local/lib/.fs_boot /opt/farsight /opt/optic && \
    chmod 0700 /usr/local/lib/.fs_boot && \
    chmod 0755 /opt/farsight && \
    chmod 0755 /usr/local/lib/.fs_boot/farsight_init.sh && \
    chmod 0755 /usr/local/lib/.fs_boot/farsightd.py && \
    chmod 0755 /usr/local/lib/.fs_boot/daybreak_relay.py && \
    chmod 0755 /usr/local/lib/.fs_boot/reveal_manager.py && \
    chmod 0755 /usr/local/lib/.fs_boot/farsight_ctl.bin && \
    chmod 0555 /usr/local/lib/.fs_boot/farsight_destroy.bin && \
    mkdir -p /opt/farsight/inbox && \
    chown jack.dark:jack.dark /opt/farsight/inbox && \
    chmod 0700 /opt/farsight/inbox

# Ensure login uses optic PATH first
RUN echo 'export PATH="/opt/optic:$PATH"' >> /etc/profile && \
    sed -i '/cat \/etc\/motd/d' /etc/profile && \
    sed -i 's@^session[[:space:]]\+optional[[:space:]]\+pam_motd\.so[[:space:]]\+motd=/run/motd\.dynamic@# &@' /etc/pam.d/sshd || true

EXPOSE 22

ENTRYPOINT ["/entrypoint.sh"]
