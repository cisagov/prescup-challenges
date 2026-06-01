#!/bin/bash
# Start the ssh server
/setup.sh
rm -rf /setup.sh
/usr/sbin/sshd -D
