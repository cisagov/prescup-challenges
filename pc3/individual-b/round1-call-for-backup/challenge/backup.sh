#!/bin/bash

# Copyright 2022 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

# This script generates a local backup

backup_name=$1
shift;

tar -cvzPf /home/user/${backup_name} --exclude /home/user/${backup_name} $@
chown user:user /home/user/${backup_name}
