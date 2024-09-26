#!/bin/bash

# Copyright 2024 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.


# file location: /var/lib/postgresql

while true; do
	sudo -u postgres pgagent -f -l 2 host=localhost port=5432 user=postgres dbname=postgres
	#echo "$(date): pgagent killed" | sudo tee -a /home/user/Desktop/tmp_log
	sleep 3
	#echo "$(date): pgagent restarting..." | sudo tee -a /home/user/Desktop/tmp_log
done
