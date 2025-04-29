# Covert Conundrum

The following VMs are running the scripts and services listed:

## attacker-wan 123.45.67.100:

- exfil.py : connects to sender.py on dmz-server
- exfil.service
- keylog.service
- keylogReceiver.py : connects to safe.py on kali-challenger1

## dmz-server 10.7.7.10:

- sender.service
- sender.py

## kali-challenger1 10.5.5.x DHCP:

- safe.service
- safe.py

## app-server 10.3.3.3:

- broadcast.service
- broadcast_spammer.py