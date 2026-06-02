FROM php:8.2-apache

# Enable PDO MySQL (mysqlnd)
RUN docker-php-ext-install pdo_mysql && a2enmod rewrite

RUN apt-get update && apt-get install -y python3 python3-pip
RUN pip3 install --break-system-packages mysql-connector-python

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

RUN mkdir /app
COPY db_seed.py /app/db_seed.py
COPY entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/db_seed.py /app/entrypoint.sh

# Make sure they can't write to the web root
RUN chown -R root:root /var/www/html && chmod -R 755 /var/www/html

# Copy app into the web root
COPY ./app/ /var/www/html/

ENTRYPOINT ["/app/entrypoint.sh"]
