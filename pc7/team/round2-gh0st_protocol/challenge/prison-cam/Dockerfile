FROM python:3.11-slim

RUN apt-get update && \
    apt-get install -y openssh-server net-tools && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN useradd -m brian && \
    echo "brian:hunt" | chpasswd && \
    mkdir -p /var/run/sshd

WORKDIR /home/brian

# Copy setup script; ALL token artifacts are created at runtime from env
COPY setup.sh /usr/local/bin/setup.sh
RUN chmod +x /usr/local/bin/setup.sh

EXPOSE 22

# Entrypoint ingests tokens from env and starts sshd (or provided CMD)
ENTRYPOINT ["/usr/local/bin/setup.sh"]
CMD []

