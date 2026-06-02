FROM debian:12-slim

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    openssh-server jq ca-certificates openssh-server ssh sudo curl iputils-ping nmap python3 pip vim nano sshpass python3-flask \
  && rm -rf /var/lib/apt/lists/*
RUN pip install requests --break-system-packages


RUN mkdir -p /run/sshd \
 && useradd -m -s /bin/bash vork

RUN echo 'vork:potatoes' | chpasswd


RUN usermod -G sudo vork 

RUN echo "vork ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/90-vork \
  && chmod 0440 /etc/sudoers.d/90-vork

RUN sed -i 's/^#PasswordAuthentication .*/PasswordAuthentication yes/' /etc/ssh/sshd_config \
 && sed -i 's/^#PermitRootLogin .*/PermitRootLogin no/' /etc/ssh/sshd_config \
 && echo "UsePAM yes" >> /etc/ssh/sshd_config

COPY start-next.sh /usr/local/bin/start-next.sh
RUN chmod +x /usr/local/bin/start-next.sh

ENV mediumtoken=TESTTOKEN2

EXPOSE 22
CMD ["/usr/local/bin/start-next.sh"]
