#!/bin/bash
ansible-playbook -i /opt/playbooks/inventory.ini /opt/playbooks/tools_ftp_playbook.yml
while true; do
ansible-playbook -i /opt/playbooks/inventory.ini /opt/playbooks/system_check_playbook.yml
sleep 15
done