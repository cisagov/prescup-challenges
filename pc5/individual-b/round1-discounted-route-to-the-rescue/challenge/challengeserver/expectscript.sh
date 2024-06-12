#!/bin/bash

# Copyright 2024 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.


set username [lindex $argv 0]
set password [lindex $argv 1]
set serverid [lindex $argv 2]
set newpassword [lindex $argv 3]

spawn ssh -o "StrictHostKeyChecking no" $serverid passwd
expect "password:"
send "$password\r"
expect "UNIX password:"
send "$password\r"
expect "password:"
send "$newpassword\r"
expect "password:"
send "$newpassword\r"
expect eof
