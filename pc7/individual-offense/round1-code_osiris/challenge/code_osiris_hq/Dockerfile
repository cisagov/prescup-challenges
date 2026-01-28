FROM ubuntu:20.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
       apache2 \
       sudo \
       python3 \
       gcc-multilib \
       make \
    && rm -rf /var/lib/apt/lists/*

# Suppress ServerName warning
RUN echo "ServerName localhost" > /etc/apache2/conf-available/servername.conf
RUN a2enconf servername

# Create application directory
RUN mkdir -p /app/
WORKDIR /app

EXPOSE 80

# Copy sources and artifacts
COPY code_osiris_v1.c ./
COPY code_osiris_v2.c ./
COPY 03_co_bof_template-pwn.py /var/www/html/
COPY 03_co_bof_template.py /var/www/html/
COPY recruit_briefing.txt /var/www/html/
COPY pattern_create.py /var/www/html/
COPY static/ /var/www/html/


# Move binaries to web root
RUN mv code_osiris_v1 /var/www/html/ 
RUN mv code_osiris_v2 /var/www/html/

# Fix permissions
RUN chmod +x /var/www/html/code_osiris_v1 /var/www/html/code_osiris_v2 /var/www/html/03_co_bof_template.py /var/www/html/03_co_bof_template-pwn.py /var/www/html/index.html /var/www/html/recruit_briefing.txt

# Entrypoint
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
