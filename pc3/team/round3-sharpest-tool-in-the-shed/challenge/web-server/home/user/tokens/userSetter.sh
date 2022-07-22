#!/bin/bash

# Copyright 2022 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

user= #insert random username here

while ! /usr/bin/mongo --eval "db.version()" > /dev/null 2>&1; do sleep 1; done
mongo --eval 'db.user.update({username:"'"$user"'"},{$set:{"group":"admin"}});' userDB
