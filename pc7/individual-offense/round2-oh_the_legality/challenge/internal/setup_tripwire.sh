#!/bin/bash
twadmin --create-polfile -S /etc/tripwire/site.key /root/tripwire_rules.txt
tripwire --init
