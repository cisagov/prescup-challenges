#!/bin/bash

# Copyright 2024 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

rm -rf /home/user/c21/inbox
rm -rf /home/user/c21/messages/*
rm -rf /home/user/c21/output/*
echo "0" > /home/user/c21/status.txt

sudo -u user sshpass -p 'tartans' scp user@k3s-server.merch.codes:/home/user/default/appdata/maildir/user@merch.codes/inbox /home/user/c21/inbox

sudo -u user python3 /home/user/c21/getMessages.py
sudo -u user python3 /home/user/c21/checkMessages.py

result=""

file_path=/home/user/c21/status.txt

value=$(head -c 1 "$file_path")

if [ "$value" -eq 0 ]; then
    result="$result GradingCheck1: Fail - No emails were found in user's malbox. Please try resending them.\n"
elif [ "$value" -eq 1 ]; then
    result="$result GradingCheck1: Fail - No emails from it-admin@merch.codes were found. You must use this account to send the messages.\n"
elif [ "$value" -eq 2 ]; then 
    result="$result GradingCheck1: Fail - No messages in user's inbox included the target link of \"yourfiles.zip\". Please resend with the appropriate URL in the message.\n"
elif [ "$value" -eq 3 ]; then
    result="$result GradingCheck1: Success - The user has clicked on your link. If you do not receive a connection, please recheck your exploitation environment and rerun the grading check.\n"
    sudo -u user sshpass -p 'Ph1sh1ngK1ng#1' ssh -t user@10.1.1.50 'bash -s' < /home/user/challengeServer/custom_scripts/infect.sh
fi

printf "$result"


