#/bin/bash -e

# Copyright 2023 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

for i in {1..150}
do
    mkdir ./keys/user$i
    ssh-keygen -q -t rsa -N "" -f ./keys/user$i/id_rsa
done
