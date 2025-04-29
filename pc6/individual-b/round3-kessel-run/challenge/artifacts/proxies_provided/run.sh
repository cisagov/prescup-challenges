#!/bin/bash
# The following runs all of the proxies together, logging their output to files and letting you exit at all of them once using CTRL-C
# You can copy the commands on lines 4-7 to run them individually if you'd like
# python ./channel/channel.py -H localhost -P 8080 -X localhost -Y 8081 
# python ./maelstrom/maelstrom.py -H localhost -P 8081 -X localhost -Y 8082 
# python ./maw/maw.py -H localhost -P 8082 -X localhost -Y 8083 
# python ./kessel/kessel.py -H localhost -P 8083 -X localhost -Y 8083 

function channel {
    cd ./channel
    python3 ./channel.py -H localhost -P 8080 -X localhost -Y 8081
    :
}

function maelstrom {
    cd ./maelstrom
    python3 ./maelstrom.py -H localhost -P 8081 -X localhost -Y 8082
    :
}

function maw {
    cd ./maw
    python3 ./maw.py -H localhost -P 8082 -X localhost -Y 8083
    :
}

function kessel {
    cd ./kessel
    python3 ./kessel.py -H localhost -P 8083 -X localhost -Y 8083
    :
}

blue=$'\033[1;34m';
green=$'\033[1;32m';
red=$'\033[1;31m';
yellow=$'\033[1;33m';
off=$'\e[m';

channel 2>&1 | tee channel.log | sed -e "s/^/$blue[Channel]$off /" & \
maelstrom 2>&1 | tee maelstrom.log | sed -e "s/^/$green[Maelstrom]$off /" & \
maw 2>&1 | tee maw.log | sed -e "s/^/$red[Maw]$off /" & \
kessel 2>&1 | tee kessel.log | sed -e "s/^/$yellow[Kessel]$off /" & wait