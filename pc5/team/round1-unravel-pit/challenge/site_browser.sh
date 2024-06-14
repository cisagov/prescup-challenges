#!/bin/bash

# Copyright 2024 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.


sites=(
"https://keycloak.merch.codes"
"https://mail.merch.codes"
"https://chat.merch.codes"
"https://10.0.0.1/"
"https://db.merch.codes"
"http://shop.merch.codes/index.html"
"http://shop.merch.codes/products.php"
"http://shop.merch.codes/admin/purchases_query.php"
)

while true; do
	url=${sites[RANDOM % ${#sites[@]}]}
	
	echo "Going to: $url"
	
	wget --no-check-certificate -O /dev/null "$url"
	
	
	sleep_time=$((RANDOM % 6 + 15))
	
	echo "sleeping for $sleep_time seconds"
	sleep "$sleep_time"
done
