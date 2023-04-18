#!/bin/bash

# Copyright 2023 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

#Replace each curl command API Key with your intel-bot API Key (instead of kyh7MFWcoP6iRm8CFY141K3nlUJgNuvm)
sleep 480
token3='ENTERTHEANSWERFORQUESTION3'
curl -k -X POST https://172.21.57.100/api/v1/messages -u intel-bot@172.21.57.100:kyh7MFWcoP6iRm8CFY141K3nlUJgNuvm --data-urlencode type=stream --data-urlencode to=General --data-urlencode topic=collab --data-urlencode content='Welcome to our R&D collaboration'
sleep 5
curl -k -X POST https://172.21.57.100/api/v1/messages -u intel-bot@172.21.57.100:kyh7MFWcoP6iRm8CFY141K3nlUJgNuvm --data-urlencode type=stream --data-urlencode to=General --data-urlencode topic=collab --data-urlencode content='We will share our test results here'
sleep 5
curl -k -X POST https://172.21.57.100/api/v1/messages -u intel-bot@172.21.57.100:kyh7MFWcoP6iRm8CFY141K3nlUJgNuvm --data-urlencode type=stream --data-urlencode to=General --data-urlencode topic=collab --data-urlencode content='The temperature required for the vaccine is '$token3
sleep 5
curl -k -X POST https://172.21.57.100/api/v1/messages -u intel-bot@172.21.57.100:kyh7MFWcoP6iRm8CFY141K3nlUJgNuvm --data-urlencode type=stream --data-urlencode to=General --data-urlencode topic=collab --data-urlencode content='The contents are very fragile. Shipping requires special packaging'
sleep 5
curl -k -X POST https://172.21.57.100/api/v1/messages -u intel-bot@172.21.57.100:kyh7MFWcoP6iRm8CFY141K3nlUJgNuvm --data-urlencode type=stream --data-urlencode to=General --data-urlencode topic=collab --data-urlencode content='We will do testing on interplanetary shipping next week.'
sleep 5
curl -k -X POST https://172.21.57.100/api/v1/messages -u intel-bot@172.21.57.100:kyh7MFWcoP6iRm8CFY141K3nlUJgNuvm --data-urlencode type=stream --data-urlencode to=General --data-urlencode topic=collab --data-urlencode content='Feel free to post supporting results from our testing here...'
