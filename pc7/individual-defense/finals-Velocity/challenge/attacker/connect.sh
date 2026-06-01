#!/bin/bash
tmux new-session -d -s session1
tmux send-keys -t session1 "while true; do sleep 5; ssh -o StrictHostKeyChecking=no -o PasswordAuthentication=no root@ubuntu09;done" Enter
