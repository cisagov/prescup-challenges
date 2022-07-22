#!/bin/bash

# Copyright 2022 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

#
# NOTE: run as "daemon" using `nc -l -k -p 5678 -c ./grade_it.sh`
#

# read first input line and save it as the rule file:
SURICATA_RULES='/etc/suricata/rules/suricata.rules'
RULE_LINE=$1
echo $RULE_LINE > $SURICATA_RULES

# check configuration (incl. rule file) validity:
CFGERR=$(/usr/bin/suricata -T 2>&1 > /dev/null)
[ $? == 0 ] || {
  echo
  echo "Suricata: Invalid config: detailed error message below:"
  echo
  echo "--------------------------------"
  echo $CFGERR
  echo "--------------------------------"
  echo
  echo "Please try again with a correct rule file!"
  echo
  exit 1
}

# flows (in grading.pcap) on which alert *should* be generated:
FL_POS='34432
34436
34440
34444
34452
34456
34460
34464'

# generate alerts:
LOGDIR=$(/usr/bin/mktemp -d)
/usr/bin/suricata -r ./grading.pcap -l $LOGDIR > /dev/null 2>&1
FLOWS=$(/usr/bin/grep -o '{TCP} \([[:digit:]]\+\.\)\{3\}[[:digit:]]\+:[[:digit:]]\+ ->' $LOGDIR/fast.log | /usr/bin/cut -d: -f2 | /usr/bin/cut -d' ' -f1 | /usr/bin/sort)
#/usr/bin/rm -rf $LOGDIR

# compute hits and fneg:
HITS=$(/usr/bin/comm -12 <(echo "$FLOWS") <(echo "$FL_POS"))
FNEG=$(/usr/bin/comm -13 <(echo "$FLOWS") <(echo "$FL_POS"))
FPOS=$(/usr/bin/comm -23 <(echo "$FLOWS") <(echo "$FL_POS"))

# count elements:
let NHITS=0; for i in $HITS; do let NHITS=1+$NHITS; done
let NFPOS=0; for i in $FPOS; do let NFPOS=1+$NFPOS; done

# percentage of hits and false positives:
let HIT_PCT=100*$NHITS/8
let FP_PCT=100*$NFPOS/16

# scoring:
# start with hit percentage:
let SCORE=$HIT_PCT
# halve score if low-enough fp count:
(($FP_PCT>0)) && let SCORE=$HIT_PCT/2
# zero score if too-high fp count:
(($FP_PCT>15)) && let SCORE=0

# print feedback:
echo
echo "Your rule identified $HIT_PCT% of valid incidents."
echo "Your rule alerted on $FP_PCT% of false positives."
echo "Your final score is: $SCORE%."
echo

# issue detailed feedback on any mistakes:
{
  for i in $FNEG $FPOS; do
    case $i in
    # $FNEG:
    34432|34436|34440|34452|34456|34460)
      echo "HINT: check query capitalization and keyword ordering!"
      ;;
    34444|34464)
      echo "HINT: check max string lengths, server behavior in limit cases!"
      ;;
    # $FPOS:
    34428|34448|34468|34470)
      echo "HINT: false alert(s) generated on non-user-creating queries!"
      ;;
    34430|34434|34438|34442|34446|34450|34454|34458|34462|34466)
      echo "HINT: false alert(s) generated on non-superuser creation!"
      ;;
    34472)
      echo "HINT: false alert(s) generated on server-to-client responses!"
      ;;
    34474)
      # NOTE: only give out this hint if it's the only problem left :)
      (($NFPOS==1)) && echo "HINT: 'superuser' is a legal account name in PostgreSQL!"
      ;;
    esac
  done
} | /usr/bin/sort -u

# assign TOKENS:
TOKENS=(d2eb835f9f117ada 0a23a2d7a47ec1e6 068e44c566b629bc 5a960fd4f8af77a5 6f0dfcb5e85b7d84)

# turn SCORE into a number of tokens (0..5) to generate/return for points
let NTOK=0
(($SCORE>=10)) && let NTOK=1
(($SCORE>=25)) && let NTOK=2
(($SCORE>=50)) && let NTOK=3
(($SCORE>=80)) && let NTOK=4
(($SCORE>99)) && let NTOK=5
echo
(($SCORE >= 10)) && echo "You get $NTOK token(s):"
for ((i=0; i<$NTOK; i++)); do
  echo ${TOKENS[$i]}
done
