#!/bin/bash

# Copyright 2023 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

port=28216
klist=364764 556893 602702 912521 749644 215285 895790 981308 326878 532705
keyarray=( $klist )  #This simply converts the number list to an array

sleep 300

#This client script will rotate through each of the ten keys from the array with random sleeps in between, and then start the sequence over. The keys are always used in the order they are listed above.
while true
do
        for str in ${keyarray[@]};
        do
                echo -n "Sending key value of: $str" | nc 133.45.152.250 $port &
                sleep 5
                pkill -x nc
                sleep $(($RANDOM%90+45))
        done
done

