#!/bin/bash
hospital="ssh -i /root/.ssh/hospital_id_rsa -o StrictHostKeyChecking=no grader@hospital_server"

testfilecheck=$(($($hospital ls -lsa /home/user/ | grep testfile | wc -l) + $($hospital ls /data/ | grep gpg | wc -l)))

echo $testfilecheck

if [ "$testfilecheck" -eq 0 ]; then
  exit 0
else
  exit 2
fi
