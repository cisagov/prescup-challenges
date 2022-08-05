#!/bin/bash

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