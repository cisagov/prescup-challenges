FROM debian:bookworm-slim
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update -y && apt-get upgrade -y \
 && apt-get install -y --no-install-recommends \
      squid-openssl apache2-utils ca-certificates openssl dos2unix \
 && rm -rf /var/lib/apt/lists/*

# Proxy auth file (create ./squid/passwd before build)
COPY passwd /etc/squid/passwd
RUN chmod 640 /etc/squid/passwd && chown proxy:proxy /etc/squid/passwd
RUN dos2unix /etc/squid/passwd

# use a pre-made CA (created with above openssl command)
COPY ctf-proxy-ca.key  /etc/squid/ca/ctf-proxy-ca.key
COPY ctf-proxy-ca.pem  /etc/squid/ca/ctf-proxy-ca.pem
RUN dos2unix /etc/squid/ca/ctf-proxy-ca.key /etc/squid/ca/ctf-proxy-ca.pem \
 && chmod 640 /etc/squid/ca/ctf-proxy-ca.key \
 && chmod 644 /etc/squid/ca/ctf-proxy-ca.pem \
 && chown -R proxy:proxy /etc/squid/ca

# Init ssl_db (helper path for Bookworm)
RUN /usr/lib/squid/security_file_certgen -c -s /var/lib/ssl_db -M 4MB

# Ensure ownership/permissions for Squid (runs as 'proxy')
RUN chown -R proxy:proxy /var/lib/ssl_db

# Logs dir must exist & be writable
RUN mkdir -p /var/log/squid && chown -R proxy:proxy /var/log/squid

# Config
COPY squid.conf /etc/squid/squid.conf
RUN dos2unix /etc/squid/squid.conf

EXPOSE 3128
# Add -N to stay in foreground; -d 1 gives startup debug to docker logs
CMD ["/usr/sbin/squid","-N","-d","1","-f","/etc/squid/squid.conf"]
