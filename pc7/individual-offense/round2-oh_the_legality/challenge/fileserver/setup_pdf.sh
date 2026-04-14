#!/bin/bash
qpdf --encrypt '' '' 256 -- /root/secret.pdf /var/www/html/flag.pdf
service apache2 start
