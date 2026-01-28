FROM dorowu/ubuntu-desktop-lxde-vnc:latest


RUN apt-get update --allow-insecure-repositories
RUN apt-get install -y ftp inetutils-ping dnsutils firefox nmap nano telnet ssh netcat php git build-essential libssl-dev pkg-config

RUN apt install gpgv2 autoconf bison build-essential postgresql libaprutil1 libgmp3-dev libpcap-dev openssl libpq-dev libreadline6-dev libsqlite3-dev libssl-dev locate libsvn1 libtool libxml2 libxml2-dev libxslt-dev wget libyaml-dev ncurses-dev  postgresql-contrib xsel zlib1g zlib1g-dev -y
RUN curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall
RUN chmod 755 msfinstall
RUN ./msfinstall

EXPOSE 80

ENTRYPOINT ["/startup.sh"]