#!/bin/bash
pid=$(lsof -t -i :4444)
md5=$(md5sum /proc/$pid/exe | cut -d ' ' -f 1)
if [ $md5 == 237abcdd0dd6eb2ae96d88ed6c065791 ]
then
    echo success
else
    echo fail
    rm /tmp/md5_grader.sh
    exit 1
fi
