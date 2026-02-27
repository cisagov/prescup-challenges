# All compilation happens at runtime (start.sh) for dynamic password injection
FROM ubuntu:20.04

ENV DEBIAN_FRONTEND=noninteractive \
    APT_OPTS="-y --no-install-recommends --fix-missing"

# Update package lists (revert to standard flow)
RUN apt-get update -qq && \
    apt-get clean && rm -rf /var/lib/apt/lists/* /var/cache/apt/*

# Install in stages to isolate failures and manage disk space
RUN apt-get update -qq && \
    apt-get install -qq $APT_OPTS \
    ca-certificates \
    apt-utils \
    gnupg2 \
    software-properties-common && \
    apt-get clean && rm -rf /var/lib/apt/lists/* /var/cache/apt/*

# Install core tools (trimmed)
RUN apt-get update -qq && \
    apt-get install -qq $APT_OPTS \
    apache2 \
    git \
    unzip \
    vim \
    supervisor \
    openssh-server \
    net-tools \
    sudo && \
    apt-get clean && rm -rf /var/lib/apt/lists/* /var/cache/apt/*

# Install Python, build tools, and Java compiler (runtime has no internet)
RUN apt-get update -qq && \
    apt-get install -qq $APT_OPTS \
    python3 \
    python3-pip \
    gcc \
    build-essential \
    default-jdk-headless && \
    apt-get clean && rm -rf /var/lib/apt/lists/* /var/cache/apt/* /usr/share/doc/* /usr/share/man/*

# Install MariaDB early (before large downloads) and clean aggressively
RUN apt-get update -qq && \
    apt-get install -qq $APT_OPTS \
    mariadb-server \
    mariadb-client && \
    apt-get clean && rm -rf /var/lib/apt/lists/* /var/cache/apt/* /usr/share/doc/* /usr/share/man/* && \
    rm -rf /var/lib/mysql/*

# Install PHP and extensions
RUN apt-get update -qq && \
    apt-get install -qq $APT_OPTS \
    php7.4 \
    php7.4-mysql \
    php7.4-intl \
    php7.4-gd \
    php7.4-xml \
    php7.4-mbstring \
    php7.4-zip || \
    apt-get install -qq $APT_OPTS php7.4 php7.4-mysql php7.4-intl php7.4-gd php7.4-xml php7.4-mbstring && \
    apt-get clean && rm -rf /var/lib/apt/lists/* /var/cache/apt/* /usr/share/doc/* /usr/share/man/*

# Create CTF directory structure
RUN mkdir -p /ctf/wiki /ctf/flag

# Create users for services
RUN useradd -m -s /bin/bash wiki_user && \
    useradd -m -s /bin/bash ctf_user

# Set up the final flag (only accessible by root) - moved to runtime start.sh

# MediaWiki
WORKDIR /tmp

# Install WP-CLI with retry logic (install curl temporarily)
RUN apt-get update -qq && \
    apt-get install -qq $APT_OPTS curl && \
    (curl -O https://raw.githubusercontent.com/wp-cli/builds/gh-pages/phar/wp-cli.phar || \
     curl -O https://raw.githubusercontent.com/wp-cli/builds/gh-pages/phar/wp-cli.phar) && \
    chmod +x wp-cli.phar && \
    mv wp-cli.phar /usr/local/bin/wp && \
    mkdir -p /var/www/.wp-cli/cache && \
    chown -R www-data:www-data /var/www/.wp-cli && \
    chmod -R 755 /var/www/.wp-cli && \
    apt-get purge -y curl && \
    apt-get autoremove -y && \
    apt-get clean && rm -rf /var/lib/apt/lists/* /var/cache/apt/*

# MediaWiki base and copy files over from pre-existing site
RUN mkdir -p /ctf/wiki && \
    mkdir -p /var/www/.wp-cli/cache && \
    chown -R www-data:www-data /var/www/.wp-cli && \
    chmod -R 755 /var/www/.wp-cli

# WordPress - Install specific version and configure
RUN mkdir -p /var/www/blog && \
    mkdir -p /var/www/blog/wp-content/uploads && \
    mkdir -p /var/www/blog/wp-content/plugins && \
    chown -R www-data:www-data /var/www/blog && \
    chmod -R 755 /var/www/blog && \
    chmod 777 /var/www/blog/wp-content/uploads && \
    (sudo -u www-data wp core download --path=/var/www/blog --version=5.5 --force || \
     sudo -u www-data wp core download --path=/var/www/blog --version=5.5 --force)

# Copy WordPress config
COPY config/wordpress/wp-config.php /var/www/blog/
RUN chown www-data:www-data /var/www/blog/wp-config.php

# Copy and prepare plugins
COPY config/wordpress/plugins/ /ctf/config/wordpress/plugins/

# Install the vulnerable wp-file-manager plugin
RUN mkdir -p /var/www/blog/wp-content/plugins/wp-file-manager && \
    cp -r /ctf/config/wordpress/plugins/wp-file-manager/* /var/www/blog/wp-content/plugins/wp-file-manager/ && \
    chown -R www-data:www-data /var/www/blog/wp-content/plugins/wp-file-manager && \
    chmod -R 755 /var/www/blog/wp-content/plugins/wp-file-manager

WORKDIR /tmp
RUN apt-get update -qq && \
    apt-get install -qq $APT_OPTS wget && \
    (wget https://releases.wikimedia.org/mediawiki/1.39/mediawiki-1.39.0.tar.gz || \
     wget https://releases.wikimedia.org/mediawiki/1.39/mediawiki-1.39.0.tar.gz) && \
    tar -xzf mediawiki-1.39.0.tar.gz && \
    mv mediawiki-1.39.0/* /ctf/wiki/ && \
    rm -rf mediawiki-1.39.0* && \
    chown -R www-data:www-data /ctf/wiki && \
    apt-get purge -y wget && \
    apt-get autoremove -y && \
    apt-get clean && rm -rf /var/lib/apt/lists/* /var/cache/apt/*

RUN (pip3 install pywikibot || pip3 install pywikibot)

# Copy service files and configurations
COPY config/ /ctf/config/
RUN chmod +x /ctf/config/*.sh
# COPY examples/ /ctf/examples/
COPY --chown=www-data:www-data wiki/ /ctf/wiki/
# scott_patch.jar is compiled at runtime in start.sh with dynamic password injection
# A placeholder copy is placed here; start.sh overwrites it with the real one
COPY jar/scott_patch.jar /ctf/scott_patch.jar

# Copy custom logo if it exists
COPY wiki/logo/ /tmp/logo/

# Remove default Apache page so it doesn't conflict
RUN rm -rf /var/www/html

# Apache for both services
RUN echo "Listen 8081" >> /etc/apache2/ports.conf 
COPY config/apache/wiki.conf /etc/apache2/sites-available/000-default.conf
COPY config/apache/blog.conf /etc/apache2/sites-available/blog.conf
RUN a2ensite blog.conf
RUN a2enmod rewrite && a2enmod php7.4

# Note: MariaDB initialization happens at runtime in start.sh

# MediaWiki
COPY config/mediawiki/LocalSettings.php /ctf/wiki/LocalSettings.php

# supervisor conf
COPY config/supervisor/supervisord.conf /etc/supervisor/conf.d/supervisord.conf

# SSH (for potential lateral movement), bit I'm not gonna generate keys or set passwords yet
# RUN mkdir /var/run/sshd 
#     # RUN ssh-keygen -A && \
#     # echo 'ctf_user:ctf_password123' | chpasswd && \
#     # echo 'wiki_user:wiki_pass_weak' | chpasswd && \
#     # echo 'root:root_ctf_pass_456' | chpasswd

# Set SUID bit on the privilege escalation binary
# COPY config/privesc/vuln_binary /usr/local/bin/vuln_binary
# RUN chmod u+s /usr/local/bin/vuln_binary && \
#     chown root:root /usr/local/bin/vuln_binary

# Create directories that need to exist
RUN mkdir -p /ctf/wiki/images && \
    mkdir -p /ctf/wiki/resources/assets && \
    mkdir -p /var/log/supervisor

# Set proper permissions
COPY --chown=www-data:www-data wiki/ /ctf/wiki/
RUN chmod 755 /ctf/wiki

# Copy custom logo if it exists
RUN if [ -f /tmp/logo/wiki.png ]; then \
        cp /tmp/logo/wiki.png /ctf/wiki/resources/assets/wiki.png && \
        chown www-data:www-data /ctf/wiki/resources/assets/wiki.png; \
    fi

# Expose ports
EXPOSE 80 8081

# Copy C source for runtime compilation (password injected at container start)
COPY config/privesc/vuln_binary.c /ctf/privesc/vuln_binary.c

# Copy Java source and manifest for runtime compilation
COPY jar/VulnJar.java /ctf/jar/VulnJar.java
COPY jar/manifest.txt /ctf/jar/manifest.txt

# Copy Apache Mods
COPY config/apache/mpm_prefork.conf /etc/apache2/mods-available/mpm_prefork.conf

# Create startup script
COPY config/start.sh /start.sh
RUN chmod +x /start.sh

# Set working directory
WORKDIR /ctf

# Start services
CMD ["/start.sh"]
