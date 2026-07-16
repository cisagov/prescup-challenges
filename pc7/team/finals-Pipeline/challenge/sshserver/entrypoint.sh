#!/bin/bash
# Start the ssh server
/setup.sh
rm -rf /setup.sh
exec env -u TOKEN1 /usr/sbin/sshd -D