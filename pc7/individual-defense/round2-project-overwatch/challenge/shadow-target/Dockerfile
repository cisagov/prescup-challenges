FROM debian:bullseye-slim

ENV DEBIAN_FRONTEND=noninteractive

# Install required tools
RUN apt update && \
    apt install -y --no-install-recommends \
    net-tools \
    iproute2 \
    curl \
    iputils-ping \
    tcpdump \
    openssh-client \
    openssh-server \
    mailutils \
    postfix \
    sqlite3 \
    zip \
    unzip \
    vim \
    less \
    grep \
    whois \
    jq \
    lsof \
    bash \
    coreutils \
    sudo \
    binwalk \
    foremost \
    util-linux \
    e2fsprogs \
    build-essential \
    gcc \
    make \
    libc6-dev \
    busybox-static && \
    apt clean && \
    rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

RUN mkdir -p /var/spool/postfix/maildrop && \
    chown -R postfix:postfix /var/spool/postfix

# Configure and enable SSH
RUN mkdir -p /var/run/sshd && \
    sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    echo 'PermitRootLogin yes' >> /etc/ssh/sshd_config && \
    echo "root:rootpassword" | chpasswd && \
    passwd -l root

# Disable shell history globally
RUN echo 'export HISTFILE=' >> /etc/profile && \
    echo 'unset HISTFILE' >> /etc/bash.bashrc

# # Create specter user
# RUN useradd -m -s /bin/bash specter && \
#     chown specter:specter /home/specter/.bashrc && \
#     echo 'specter:fieldwork' | chpasswd && \
#     echo 'specter ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers

# Create specter user with limited sudo (tcpdump + timeout only)
RUN useradd -m -s /bin/bash specter && \
    chown specter:specter /home/specter/.bashrc && \
    echo 'specter:fieldwork' | chpasswd && \
    rm -f /etc/sudoers.d/030-specter-tcpdump && \
    sh -c 'printf "Defaults:specter !requiretty\nspecter ALL=(root) NOPASSWD: /usr/bin/tcpdump\n" > /etc/sudoers.d/030-specter-tcpdump' && \
    chmod 0440 /etc/sudoers.d/030-specter-tcpdump

# Inject history to command output from file.
RUN echo 'history -n ~/.bash_history' >> /home/specter/.bashrc && \
    chown specter:specter /home/specter/.bashrc

# Set workdir and drop into user
USER specter
WORKDIR /home/specter

# Entrypoint for runtime token injection
USER root
COPY inject/runtime_inject.sh /root/runtime_inject.sh
COPY inject/messages.db.template /root/messages.db.template
COPY inject/android_dump /root/android_dump
COPY ./folder-image.png /tmp/folder-image.png
RUN chmod +x /root/runtime_inject.sh

ENTRYPOINT ["/root/runtime_inject.sh"]
CMD ["/usr/sbin/sshd", "-D"]
