#!/bin/bash

# Copyright 2025 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.


# Sends Syslog message to defined servers 
# This is controled by a systemd timer 

TARGET_SERVER_01="10.1.1.151" # Base-Ubuntu Server 
TARGET_SERVER_02="10.1.1.152" # Logging-Ubuntu Server 

# Get Token using guestinfo 
CODE_01=$(vmtoolsd --cmd "info-get guestinfo.token1")
CODE_02=$(vmtoolsd --cmd "info-get guestinfo.token2")

# Send the log entry via syslog
logger -n "$TARGET_SERVER_01" -P 514 -t lab_completion "Phase 1 Completed. Token: $CODE_01"
logger -n "$TARGET_SERVER_02" -P 514 -t lab_completion "Phase 2 Completed. Token: $CODE_02"
