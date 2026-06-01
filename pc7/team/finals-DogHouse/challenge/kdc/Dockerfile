FROM debian:bookworm

RUN apt update && apt install -y krb5-kdc krb5-admin-server krb5-pkinit vim dnsutils curl procps ssh dos2unix

# Set realm and domain
ENV REALM=CTF.LOCAL
ENV DOMAIN=ctf.local
ENV KRB5_KDC_PROFILE=/etc/krb5kdc/kdc.conf
#ENV PASSWORD="password1"

RUN echo "$DOMAIN" > /etc/hostname

COPY krb5.conf /etc/krb5.conf
COPY kdc.conf /etc/krb5kdc/kdc.conf

COPY cacert.pem /etc/krb5kdc/cacert.pem
COPY extensions.kdc /etc/krb5kdc/extensions.kdc
COPY kdckey.pem /etc/krb5kdc/kdckey.pem
COPY kdc.pem /etc/krb5kdc/kdc.pem

#RUN mkdir /root/.ssh
COPY pub_id_rsa /root/.ssh/id_rsa.pub
RUN chmod 600 /root/.ssh/id_rsa.pub
RUN dos2unix /root/.ssh/id_rsa.pub

COPY id_rsa /root/.ssh/id_rsa
RUN chmod 600 /root/.ssh/id_rsa
RUN dos2unix /root/.ssh/id_rsa

COPY kdc-init.sh /kdc-init.sh
RUN chmod +x /kdc-init.sh

EXPOSE 88/udp 88/tcp 749/tcp 464/tcp
CMD ["/kdc-init.sh"]
