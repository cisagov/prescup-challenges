#!/bin/bash
ssh_check_failed=0
ssh -o BatchMode=yes -o PasswordAuthentication=no -o StrictHostKeyChecking=no -o ConnectTimeout=2 root@ubuntu09 id
if [[ $? == 0 ]]
then
    echo ssh check failed
    ssh_check_failed=1
fi
if [[ $ssh_check_failed == 0 ]]
then
    echo ssh check passed
fi
