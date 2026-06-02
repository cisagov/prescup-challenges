FROM mysql:8.0

# Runtime env (the entrypoint will use these to create the DB/user)
ENV MYSQL_DATABASE=pop \
    MYSQL_USER=user \
    MYSQL_PASSWORD=password \
    MYSQL_ROOT_PASSWORD=password

# Optional: seed schema/data
COPY init.sql /docker-entrypoint-initdb.d/00_init.sql
