#!/bin/bash
while true
do
    if [[ -f /tmp/6470e394cbf6dab6a91682cc8585059b ]]
    then
        rm -rf /tmp/6470e394cbf6dab6a91682cc8585059b
        /run.sh &
    fi
    sleep 3
done
