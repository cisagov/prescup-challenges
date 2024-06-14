#!/bin/bash

# Copyright 2024 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.


cookie=$(cat /home/user/cookies.txt | grep pritunl | rev | cut -d $'\t' -f1 | rev)
while IFS= read -r directory
do
curl -k 'https://files.merch.codes/'"$directory" -H "User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0" -H "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8" -H "Accept-Language: en-US,en;q=0.5" -H "Connection: keep-alive" -H "Cookie: pritunl-zero=$cookie" -H "Upgrade-Insecure-Requests: 1" -H "Sec-Fetch-Dest: document" -H "Sec-Fetch-Mode: navigate" -H "Sec-Fetch-Site: none" -H "Sec-Fetch-User: ?1" -H "If-Modified-Since: Sat, 29 Apr 2023 03:25:27 GMT" -H "If-None-Match: '52e-5fa7124130513-gzip'" --output /home/user/output"$directory".html
done < /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt
