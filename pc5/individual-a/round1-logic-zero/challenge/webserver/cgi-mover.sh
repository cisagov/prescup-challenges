#!/bin/bash

# Copyright 2024 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.


cgi_filename=$(vmtoolsd --cmd "info-get guestinfo.cgi_filename")
cp /var/www/html/cgi-bin/replacewithdigits.cgi /var/www/html/cgi-bin/$cgi_filename.cgi
cp /var/www/html/cgi-bin/replacewithdigits.cgi /usr/lib/cgi-bin/$cgi_filename.cgi
