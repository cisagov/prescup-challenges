#!/bin/bash
echo $TOKEN3 > /tmp/token3.txt
unset TOKEN3
cd /home/runner
sudo -u runner /tmp/setup.sh
rm /tmp/setup.sh

/usr/bin/ssh-keygen -A
/usr/sbin/sshd -D &

#run_playbook.sh as ansibleadm user in background
sudo -u ansibleadm /home/ansibleadm/run_playbook.sh &

cd /home/runner
sudo -u runner act_runner --config /home/runner/config.yaml daemon
