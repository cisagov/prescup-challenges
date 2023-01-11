#!/bin/bash

# Copyright 2023 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

hname=$(vmtoolsd --cmd "info-get guestinfo.hostname")

file="/etc/hostname"
hsname=$(cat $file)

if [ -n $hname ] && [ $hname != $hsname ]
then
	hostnamectl set-hostname $hname
	echo 127.0.0.1 $hname > /etc/hosts
	echo 127.0.0.1 localhost >> /etc/hosts
	echo ::1 $hname >> /etc/hosts
	echo ::1 localhost >> /etc/hosts
fi
