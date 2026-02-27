FROM mysql:9.3.0

# Set script as executable
COPY warehouse.sql /docker-entrypoint-initdb.d/01-schema.sql
COPY seed.sql /docker-entrypoint-initdb.d/02-seed.sql
