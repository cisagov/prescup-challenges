#!/bin/bash
pid=$(ss -natup | grep 4444 | cut -d ',' -f 2 | cut -d '=' -f '2')
if [[ $(echo $pid | grep ' ' | wc -l) != 0 ]]
then
    pid=$(sudo -u ops-user ss -natup | grep 4444 | cut -d ',' -f 2 | cut -d '=' -f '2')
fi
md5=$(md5sum /proc/$pid/exe | cut -d ' ' -f 1)
if [ $md5 == 237abcdd0dd6eb2ae96d88ed6c065791 ]
then
    echo success
else
    echo fail
    rm /tmp/md5_grader.sh
    exit 1
fi
