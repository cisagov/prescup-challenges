#!/bin/bash

# Copyright 2023 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

key=184303
port=25490

sleep 300

#This client script will simply send the same key over and over with a random sleep value in between iterations
while :
do
        echo -n "Sending key value of: $key" | nc 133.45.151.250 $port &
        sleep 5
        pkill -x nc
        sleep $(($RANDOM%90+45))
done

