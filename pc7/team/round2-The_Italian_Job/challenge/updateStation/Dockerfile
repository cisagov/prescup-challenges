FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1

# Base deps
RUN apt-get update && apt-get install -y \
    curl ca-certificates perl make gcc \
    python3 python3-pip strace supervisor zip unzip openssh-server iproute2 jq inetutils-ping netcat \
  && rm -rf /var/lib/apt/lists/*

# App layout and unprivileged user
RUN useradd -m -s /bin/bash user && \
    echo 'user:G3ZQD4XH' | chpasswd
RUN mkdir -p /var/run/sshd

RUN mkdir -p /home/user/.ssh
RUN mkdir -p /var/run/sshd 
COPY grader_key.pub /home/user/.ssh/authorized_keys

RUN chmod 700 /home/user/.ssh \
 && chmod 600 /home/user/.ssh/authorized_keys \
 && chown -R user:user /home/user/.ssh
RUN ssh-keygen -A

# Copy app files
COPY entrypoint.sh /
RUN chmod +x /entrypoint.sh

WORKDIR /home/user
RUN mkdir Downloads Documents Pictures Videos Music
COPY updateFiles/ /home/user/updateFiles
WORKDIR /home/user/updateFiles
RUN python3 build_tcu.py
RUN mv update.tcu ../Downloads/
WORKDIR /home/user
RUN rm -r updateFiles
RUN chown user /home/user/Downloads/update.tcu

ENTRYPOINT ["/entrypoint.sh"]