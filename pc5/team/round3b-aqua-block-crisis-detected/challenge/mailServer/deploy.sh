#!/bin/bash

# Copyright 2024 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

/etc/systemd/system/deploy/keygen.sh
/etc/systemd/system/deploy/date-swapper.sh
/etc/systemd/system/deploy/boxer.sh
/etc/systemd/system/deploy/boxer-sent.sh
find /home -name ".sent_archive" -type f | tar -czvf /var/log/backup.tar.gz -T -
chown root:adm /var/log/backup.tar.gz
chmod 660 /var/log/backup.tar.gz
sudo -u mallory bash -c "sed -i '66,87d' /home/mallory/.sent_archive"
sudo -u mallory bash -c "rm -f /home/mallory/.bash_history"
