#!/usr/bin/bash

# Copyright 2023 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

# run from `ncat -l -k -c /usr/share/prescup/pc4ncfbk.sh`

content=(
	ebdcb0ffe9d8736a5c73469174edf723
)

v=0

# read commit to 'build test':
read INPUT_LINE

export HOME=/root
cd /usr/share/prescup/local/dauntless
git config --global --add safe.directory /usr/share/prescup/local/dauntless
git checkout $INPUT_LINE
git status

echo "Building commit $INPUT_LINE, please stand by..."
for ((i=0; i<=10; i++)); do
	echo -ne "\r${i}0%"
	sleep 1
done
echo " ... complete. Testing commit $INPUT_LINE..."
sleep 5 
if grep -q ${content[$v]} src_file; then
	echo
	echo "Test Failed!"
	echo
else
	echo
	echo "Test Successful!"
	echo
fi

