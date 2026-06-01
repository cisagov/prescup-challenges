FROM php:8.2-apache

# Enable PDO MySQL (mysqlnd)
RUN docker-php-ext-install pdo_mysql && a2enmod rewrite

RUN apt-get update && apt-get install -y python3 python3-pip
RUN pip3 install --break-system-packages mysql-connector-python

RUN apt-get update && apt-get install -y openssh-server sudo
RUN mkdir -p /var/run/sshd
RUN useradd -m -s /bin/bash user && echo 'user:password' | chpasswd && usermod -aG sudo user
RUN sed -i 's/^#\?PasswordAuthentication .*/PasswordAuthentication yes/' /etc/ssh/sshd_config && sed -i 's/^#\?PermitRootLogin .*/PermitRootLogin no/' /etc/ssh/sshd_config

RUN rm -f /var/www/html/index.html

# Send PHP errors to container stderr and hide them from users
RUN set -eux; \
  { \
    echo 'display_errors=Off'; \
    echo 'display_startup_errors=Off'; \
    echo 'html_errors=Off'; \
    echo 'log_errors=On'; \
    echo 'error_log=/proc/self/fd/2'; \
    echo 'error_reporting=E_ALL & ~E_DEPRECATED & ~E_NOTICE'; \
  } > /usr/local/etc/php/conf.d/zz-logging.ini

# Make sure they can't write to the web root
RUN chown -R root:root /var/www/html && chmod -R 755 /var/www/html

# Copy app into the web root
COPY ./app/ /var/www/html/

# They need to start Apache
ENTRYPOINT []
CMD ["/usr/sbin/sshd", "-D", "-e"]