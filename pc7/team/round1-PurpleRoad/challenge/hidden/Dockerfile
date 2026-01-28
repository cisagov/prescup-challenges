FROM ubuntu:20.04

RUN apt update
RUN apt install -y openssh-server \
    sudo \
    iproute2 \
    python3 \
    nano \
    vim \
    dos2unix \ 
    curl


COPY token.txt /token.txt
RUN useradd -m user && echo 'user:hiddenpass' | chpasswd
COPY service.py /
COPY entrypoint.sh /entrypoint.sh
RUN dos2unix /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 22


CMD ["/entrypoint.sh"]