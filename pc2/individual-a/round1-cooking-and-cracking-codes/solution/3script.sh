#!/bin/bash

# Copyright 2022 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

touch 3-output.txt
for i in {1..999}
do
    echo "$i" >> 3-output.txt
    echo -n "$i" | sha1sum >> 3-output.txt
done
