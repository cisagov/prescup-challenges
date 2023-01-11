#!/bin/bash

# Copyright 2023 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

apikey='ENTERZULIPAPIKEYFORbackup-bot'
mkdir -p /etc/api
echo email:backup-bot@172.21.57.100 > /etc/api/zulip.keys
echo apikey:$apikey >> /etc/api/zulip.keys
echo "Tested to pull single messages by ID" >> /etc/api/zulip.keys
