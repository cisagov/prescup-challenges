#!/bin/bash

# Copyright 2023 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

/home/$USER/Desktop/challenge/scripts/attacker_transfer.sh
(crontab -l ; echo "* * * * * "/home/$USER/Desktop/challenge/scripts/attacker_transfer.sh"")| crontab -
