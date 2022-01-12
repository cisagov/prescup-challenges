#!/bin/bash

# Copyright 2022 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

# associative array of commander and moonbase IP addresses:
declare -A LEADERSHIP_IPS=(
	['44.106.35.11']='moonbaseA'
	['44.2.22.75']='moonbaseB'
	['44.91.84.131']='moonbaseC'
	['27.242.37.2']='akbar'
	['62.143.73.187']='kenobi'
	['128.237.119.24']='tarkin'
)

# parse IP addresses submitted via $* and count hits and false positives:
let FPOS=0
let MOON=0
let CMDR=0
for A in $(echo $* | grep -Eo '([0-9]{1,3}[\.]){3}[0-9]{1,3}' | sort -u); do
	if [ -n "${LEADERSHIP_IPS[$A]}" ]; then
		if [[ "${LEADERSHIP_IPS[$A]}" == "moonbase"* ]]; then
			let MOON++
		else
			let CMDR++
		fi
	else
		let FPOS++
	fi
done

# compute score:
let SCORE=$(echo "scale=10; (($MOON * 2 + $CMDR) / (${#LEADERSHIP_IPS[@]} * 1.5) - $FPOS / ${#LEADERSHIP_IPS[@]}) * 10" | bc | cut -d. -f1)
if ((SCORE<0)); then
	let SCORE=0
fi

let HITS=MOON+CMDR

echo "You entered $HITS correct IPs and $FPOS incorrect IPs; Score: ${SCORE}0%"
