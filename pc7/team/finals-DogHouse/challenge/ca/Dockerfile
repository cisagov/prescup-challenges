FROM python:3.12-slim

# openssl + ldap deps
RUN apt-get update && apt-get install -y --no-install-recommends \
    openssl ca-certificates ldap-utils && \
    rm -rf /var/lib/apt/lists/*

# app
RUN pip install flask ldap3

# CA layout
RUN mkdir -p /ca/certs /ca/private /ca/newcerts
COPY openssl.cnf /etc/ssl/openssl.cnf

COPY ca.crt /ca/certs/ca.crt
COPY ca.key /ca/private/ca.key

COPY cacert.pem /ca/cacert.pem
COPY cakey.pem /ca/cakey.pem
COPY extensions.client /etc/ssl/extensions.client
COPY extensions.kdc /ca/extensions.kdc

COPY kdc.csr /ca/kdc.csr

# CA db files
RUN touch /ca/index.txt && echo 1000 > /ca/serial

# Web UI
COPY ca_ui.py /usr/local/bin/ca_ui.py
RUN chmod +x /usr/local/bin/ca_ui.py

EXPOSE 80
CMD [ "python", "/usr/local/bin/ca_ui.py" ]
