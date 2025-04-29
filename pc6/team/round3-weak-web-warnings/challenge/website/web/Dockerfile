FROM php:7.4-apache

RUN docker-php-ext-install mysqli pdo pdo_mysql && docker-php-ext-enable pdo_mysql

COPY httpd.conf /tmp/httpd.conf

RUN cat /tmp/httpd.conf >> /etc/apache2/httpd.conf

COPY logging.ini /tmp/logging.ini

RUN cat /tmp/logging.ini > /usr/local/etc/php/conf.d/logging.ini

COPY src/. /var/www/html/

RUN sed -i 's/80/8080/g' /etc/apache2/sites-available/000-default.conf /etc/apache2/ports.conf

CMD ["apache2-foreground"]
