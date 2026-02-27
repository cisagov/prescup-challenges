FROM dorowu/ubuntu-desktop-lxde-vnc:latest


RUN apt-get update --allow-insecure-repositories
RUN apt-get install -y inetutils-ping dnsutils firefox nmap nano telnet ssh netcat php git iproute2 inetutils-ping curl host mtr-tiny tcpdump iptables wireshark

EXPOSE 80

ENTRYPOINT ["/startup.sh"]