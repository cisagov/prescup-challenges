#!/bin/bash

# Copyright 2024 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.


agent_number=`vmtoolsd --cmd "info-get guestinfo.agent_compromised"`
agent_password=`vmtoolsd --cmd "info-get guestinfo.agent_password"`

sleep 3

firefox https://files.merch.codes &

sleep 10
xdotool key Tab
sleep 1
xdotool key Return

sleep 3
xdotool key Tab
xdotool type agent-$agent_number
sleep 3
xdotool key Tab
xdotool type $agent_password
sleep 3
xdotool key Return


sleep 5

xdotool key "ctrl+w"
sleep 2

pkill firefox
