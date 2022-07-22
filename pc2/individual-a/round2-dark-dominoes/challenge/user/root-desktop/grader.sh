#!/bin/bash

# Copyright 2022 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

FILE1=/lib/php/og
FILE2=/home/guy/Public/c1
FILE3=/root/Downloads/c2

if [ ! -f "$FILE1" ]
then
	if [ ! -f "$FILE2" ]
	then
		if [ ! -f "$FILE3" ]
		then
			expect /root/Desktop/tf
			echo "Congrats," `cat /home/user/Desktop/flag.txt`
		else
			echo "You have not eradicated the three malicious scripts yet"
		fi
	else
		echo "You have not eradicated the three malicious scripts yet"
	fi
else
	echo "You have not eradicated the three malicious scripts yet"
fi
