#!/bin/bash

# Copyright 2022 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.


until /home/student/driver/victim.py; do
	echo "waiting a bit to respawn..." >&2
	sleep 60
done
