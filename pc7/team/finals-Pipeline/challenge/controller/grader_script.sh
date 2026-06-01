#!/bin/bash
ansible-playbook -i /opt/playbooks/inventory.ini /home/ansibleadm/grader_playbook.yml
yml_code=$?

/home/ansibleadm/grader.py 
py_code=$?

if [ $yml_code -eq 0 ] && [ $py_code -eq 0 ]; then
  echo "All checks passed."
  echo "PCCC{playbook_overwrite_token}"
  exit 0
else
  echo "One or more checks failed."
  exit 1
fi
