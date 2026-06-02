FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

ARG USERNAME=user
ARG PASSWORD=password

# Install packages
RUN apt-get update && apt-get install -y --no-install-recommends \
    openssh-server \
    ca-certificates \
    bash \
    curl \
    vim \
    passwd \
    sudo \
 && rm -rf /var/lib/apt/lists/*

RUN useradd -m -s /bin/bash -G sudo "$USERNAME" \
 && echo "$USERNAME:$PASSWORD" | chpasswd

RUN echo "$USERNAME ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/90-$USERNAME \
  && chmod 0440 /etc/sudoers.d/90-$USERNAME

# Prepare sshd
RUN mkdir -p /var/run/sshd
EXPOSE 22

CMD ["/bin/sh","-c","ssh-keygen -A && exec /usr/sbin/sshd -D -e"]
