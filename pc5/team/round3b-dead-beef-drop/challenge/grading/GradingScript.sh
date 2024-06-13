#!/bin/bash

# Copyright 2024 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.


# count how many times a string contains a given character (all lower case)
chr_cnt() {
	local STR="$1"
	local CHR="$2"
	awk -F"${CHR,*}" '{print NF-1}' <<< "${STR,,*}"
}

contains_deadbeef_anagram() {
	let local ACT=$(chr_cnt "$1" "a")
	let local BCT=$(chr_cnt "$1" "b")
	let local DCT=$(chr_cnt "$1" "d")
	let local ECT=$(chr_cnt "$1" "e")
	let local FCT=$(chr_cnt "$1" "f")
	if ((ACT>=1 && BCT>=1 && DCT>=2 && ECT>=3 && FCT>=1)); then
		return 0 # /bin/true
	fi
	return 1 # /bin/false
}

# compute expected server response locally
exp_response() {
	local STR="$1"
	local KEY='f00b4rb1a4ccdddddeadbeefccccdddd' # pre-shared with server
	echo -n "${STR::16}${KEY}${STR:16}" | /bin/md5sum | /bin/cut -d' ' -f1
}

# request response string from server
get_response() {
	local SRV='nat-fw.us'
	local PRT='31337'
	echo -n "$1" | /bin/nc -w 6 $SRV $PRT 2>/dev/null | tr '\0' '\n'
}

# empirically, approx. 12% of these will contain anagrams of "deadbeef"
random_string() {
	echo $RANDOM | md5sum | cut -d' ' -f1
}

# test a generated string
verify_str() {
	local REXP=$(exp_response "$1")
	local RGET=$(get_response "$1")
	[ "$REXP" == "$RGET" ] && return 0 # /bin/true
	return 1 # /bin/false
}

# false negatives: how many "deadbeef" anagrams are mistakenly accepted?
calc_false_neg() {
	for ((i=0, FN=0; i<10; )); do
		RS=$(random_string)
		# only interested in "offending" strings:
		! contains_deadbeef_anagram $RS && continue
		let i++
		verify_str $RS && let FN++
	done
	echo "$FN"
}

# false positives: how many non-"deadbeef"-anagrams are mistakenly rejected?
calc_false_pos() {
	for ((i=0, FP=0; i<10; )); do
		RS=$(random_string)
		# only interested in "non-offending" strings:
		contains_deadbeef_anagram $RS && continue
		let i++
		! verify_str $RS && let FP++
	done
	echo "$FP"
}

# grading check for the "smaller" (queueing) portion:
check_queueing() {
	let local IL=$(ssh root@nat-fw.us iptables-save | \
		grep -v "incompatible, use 'nft'" | wc -l)
	let local NL=$(ssh root@nat-fw.us nft list ruleset | wc -l)
	local MSG=''
	((IL!=0)) && MSG="${MSG} ●  iptables rules are not allowed!;"
	((NL<=6)) && MSG="${MSG} ●  use nft ruleset for *both* NAT & userspace queueing!;"
	echo $MSG
	((IL==0 && NL>6)) && return 0 # /bin/true
	return 1 # /bin/false
}

#grading check for the "bigger" (filtering) portion:
check_filtering() {
	let local FN=$(calc_false_neg)
	let local FP=$(calc_false_pos)
	local MSG=''
	((FN!=0)) && MSG="${MSG} ●  ${FN}0pct of DEADBEEF anagrams allowed!;"
	((FP!=0)) && MSG="${MSG} ●  ${FP}0pct of valid requests rejected!;"
	echo $MSG
	((FN==0 && FP==0)) && return 0 # /bin/true
	return 1 # /bin/false
}


result=''

if MSG=$(check_queueing); then
        result="$result GradingCheck1: Success -- queueing check passed\n"
else
        result="$result GradingCheck1: Fail : $MSG\n"
fi

if MSG=$(check_filtering); then
        result="$result GradingCheck2: Success -- filtering check passed\n"
else
        result="$result GradingCheck2: Fail : $MSG\n"
fi

printf "$result"
