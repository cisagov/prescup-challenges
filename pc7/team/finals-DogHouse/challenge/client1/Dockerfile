# Dockerfile.ubuntu-client
FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive


RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y \
    iptables \
    git \
    gcc \
    ncat \
    netcat \
    curl \
    sudo \
    iproute2 \
    dnsutils \
    nmap \
    vim \
    nano \
    python3 \
    zip \
    dos2unix \
    telnet \
    ftp \
    expect \
    tcpdump \
    openssh-client openssh-server sudo && \
    useradd -m -s /bin/bash localuser1 && echo 'localuser1:6300734ff630478bb1f26f5ad9f32586' | chpasswd

RUN apt install -y krb5-user krb5-config krb5-pkinit libpam-krb5 net-tools iputils-ping less \
    sssd sssd-tools sssd-ldap libnss-sss libpam-sss ldap-utils

COPY krb5.conf /etc/krb5.conf
RUN chmod 644 /etc/krb5.conf

COPY client.pem /client.pem
# COPY client1.keytab /etc/krb5.keytab
# RUN chmod 600 /etc/krb5.keytab
# RUN dos2unix /etc/krb5.keytab

#RUN mkdir /root/.ssh
COPY pub_id_rsa /root/.ssh/authorized_keys
RUN chmod 600 /root/.ssh/authorized_keys
RUN dos2unix /root/.ssh/authorized_keys

COPY cacert.pem /usr/local/share/ca-certificates/ctf-ca.crt
RUN dos2unix /usr/local/share/ca-certificates/ctf-ca.crt
RUN update-ca-certificates
RUN chmod 774 /usr/local/share/ca-certificates/ctf-ca.crt

# SSSD config: LDAP for identities; Kerberos for auth
RUN mkdir -p /etc/sssd
COPY sssd.conf /etc/sssd/sssd.conf
RUN chmod 600 /etc/sssd/sssd.conf
RUN dos2unix /etc/sssd/sssd.conf

RUN mkdir /home/admin
COPY networkmap.jpg /home/admin/networkmap.jpg
RUN chmod 600 /home/admin/networkmap.jpg
RUN chown -R 1100:1100 /home/admin

RUN echo '%admins ALL=(ALL:ALL) NOPASSWD:ALL' > /etc/sudoers.d/99-admins

RUN echo "session required pam_mkhomedir.so skel=/etc/skel/ umask=0022" >> /etc/pam.d/common-session

RUN sed -i 's/^#\?UsePAM.*/UsePAM yes/' /etc/ssh/sshd_config && \
    printf "\nGSSAPICleanupCredentials yes\nKerberosAuthentication yes\n" >> /etc/ssh/sshd_config

COPY entrypoint.sh /entrypoint.sh
RUN chmod 700 /entrypoint.sh
RUN dos2unix /entrypoint.sh

EXPOSE 22
ENTRYPOINT [ "/entrypoint.sh" ]
