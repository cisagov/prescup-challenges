#!/bin/bash

# Copyright 2022 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

# grab eth0 MAC address:
MAC=$(ip link show dev eth0 | tail -1 | awk '{print $2}')

# compute eth0 ipv6 link-local address:
LLA=$(atk6-address6 $MAC)

# global prefix for this machine (should be a conf option, but hardcoded for simplicity):
GPFX='2001'

# compute eth0 ipv6 global permanent address:
GPA=${LLA/fe80/$GPFX}

# process destination address:
case $NCAT_LOCAL_ADDR in
"$LLA"*)
        DST_ADR='link-local'
        let DST_IDX=0
        ;;
"$GPA"*)
        DST_ADR='global permanent'
        let DST_IDX=1
        ;;
"$GPFX"::*)
        DST_ADR='global private'
        let DST_IDX=2
        ;;
*)
        DST_ADR=$NCAT_LOCAL_ADDR
        let DST_IDX=3
        ;;
esac

# process source address:
case $NCAT_REMOTE_ADDR in
fe80::*)
        SRC_ADR='the local LAN, using a link-local address'
        let SRC_IDX=0
        ;;
"$GPFX"::*)
        SRC_ADR='the local LAN, using a global address'
        let SRC_IDX=1
        ;;
2607:fb28::*)
        SRC_ADR='a remote LAN, using a global address'
        let SRC_IDX=2
        ;;
*)
        SRC_ADR=$NCAT_REMOTE_ADDR
        let SRC_IDX=3
        ;;
esac

# grab TOKENS:
source ./tokens

# feedback to client:
echo "Hi There!"
echo
echo "You have reached my $DST_ADR address,"
echo "connecting from $SRC_ADR."
echo

IDX=$DST_IDX:$SRC_IDX
case $IDX in
0:0)
        echo "Your token #1 is: ${TOKENS[0]}"
        ;;
1:1)
        echo "Your token #2 is: ${TOKENS[1]}"
        ;;
1:2)
        echo "Your token #3 is: ${TOKENS[2]}"
        ;;
2:1)
        echo "Your token #4 is: ${TOKENS[3]}"
        ;;
2:2)
        echo "Your token #5 is: ${TOKENS[4]}"
        ;;
*)
        echo "This is unexpected!"
        echo
        echo "Please contact tech support"
        echo "and let us know how you got here!"
        ;;
esac

echo
echo "Bye!"
