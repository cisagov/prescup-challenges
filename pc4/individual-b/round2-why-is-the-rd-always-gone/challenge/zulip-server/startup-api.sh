#!/bin/bash

# Copyright 2023 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

sleep 5
api='ENTERBACKUP-BOTAPIKEY'
api="'$api'"
#Please change the id to your backup-bot's id (instead of 67)
command='sudo -u zulip psql zulip -c "UPDATE zerver_userprofile SET api_key = '$api' WHERE id = 67;"'
eval $command
touch /etc/systemd/system/startup-api-done.txt
sleep 2
reboot
