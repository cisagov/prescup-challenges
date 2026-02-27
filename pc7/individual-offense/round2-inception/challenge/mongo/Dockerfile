FROM mongo:8.0.13

# root admin (for first-boot); app DB + app user you’ll actually use from Flask
COPY *.js /docker-entrypoint-initdb.d/

RUN chmod 644 /docker-entrypoint-initdb.d/*.js

HEALTHCHECK --interval=10s --timeout=3s --retries=5 \
  CMD mongosh --quiet --eval "db.adminCommand('ping').ok" || exit 1

CMD ["mongod", "--bind_ip_all"]