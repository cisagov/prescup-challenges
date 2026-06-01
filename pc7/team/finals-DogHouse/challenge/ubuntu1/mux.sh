#!/bin/bash
user=linuxuser
pass=NixP3nguin5
tmux new-session -d -s session1
tmux send-keys -t session1 "telnet ubuntu2" Enter
sleep 1
tmux send-keys -t session1 "$user" Enter
sleep 1
tmux send-keys -t session1 "$pass" Enter
sleep 1
