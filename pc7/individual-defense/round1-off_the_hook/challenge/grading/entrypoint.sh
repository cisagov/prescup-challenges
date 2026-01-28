#!/bin/bash

# Dump all current env vars into the user’s profile
env | grep -v '^_' | awk -F= '{ print "export " $1 "=\"" $2 "\"" }' >> /home/user/.profile

# Start SSH
exec /usr/sbin/sshd -D