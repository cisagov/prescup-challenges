#!/bin/bash

# Copyright 2023 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

# generate random float in [-MIN, MAX)
gen_randf() {
  local MIN="$1"
  local MAX="$2"
  echo "($RANDOM / 32767) * ($MAX + $MIN) - $MIN" | /bin/bc -l
}

# generate random unsigned in (MIN, MAX]
gen_randu() {
  local MIN="$1"
  local MAX="$2"
  #echo "($SRANDOM % ($MAX - $MIN) + $MIN + 1)" | /bin/bc
  # bash 5.0 doesn't yet have $SRANDOM, so here's a lame workaround:
  echo "(($RANDOM * 2^16 + $RANDOM) % ($MAX - $MIN) + $MIN + 1)" | /bin/bc
}

# generate high-acceleration sample
gen_h() {
  local gx=$(gen_randf 6.0 6.0)
  local gy=$(gen_randf 6.0 6.0)
  local gz=$(gen_randf 1.5 3.0)
  local ms=$(gen_randu 0 120000)
  echo "./drvctl $gx $gy $gz $ms"
  ./drvctl $gx $gy $gz $ms
}

# generate medium-acceleration sample
gen_m() {
  local gx=$(gen_randf 3.0 3.0)
  local gy=$(gen_randf 3.0 3.0)
  local gz=$(gen_randf 1.0 2.5)
  local ms=$(gen_randu 120000 3600000)
  ./drvctl $gx $gy $gz $ms
}

# generate low-acceleration sample
gen_l() {
  local gx=$(gen_randf 2.0 2.0)
  local gy=$(gen_randf 2.0 2.0)
  local gz=$(gen_randf 0.5 2.0)
  local ms=$(gen_randu 3600000 4294967295)
  ./drvctl $gx $gy $gz $ms
}

# generate random-acceleration sample
gen_r() {
  local gx=$(gen_randf 1000.0 1000.0)
  local gy=$(gen_randf 1000.0 1000.0)
  local gz=$(gen_randf 1000.0 1000.0)
  local ms=$(gen_randu 0 4294967295)
  ./drvctl $gx $gy $gz $ms
}

# generate test samples (9 good, 11 bad, total of 20)
gen_samples() {
  {
    grep -m 3 ' OK$' <(while true; do gen_h; done); kill $!
    grep -m 2 ' EX$' <(while true; do gen_h; done); kill $!
    grep -m 3 ' OK$' <(while true; do gen_m; done); kill $!
    grep -m 2 ' EX$' <(while true; do gen_m; done); kill $!
    grep -m 3 ' OK$' <(while true; do gen_l; done); kill $!
    grep -m 2 ' EX$' <(while true; do gen_l; done); kill $!
    grep -m 5 ' EX$' <(while true; do gen_r; done); kill $!
  } | /bin/shuf
}

# compute expected response string from drive control server
exp_response() {
  local STR="$1"
  local KEY='aaaabbbbccccddddaaaabbbbccccdddd' # pre-shared w. drvctl srv unit
  echo -n "${STR::16}${KEY}${STR:16}" | /bin/md5sum | /bin/cut -d' ' -f1
}

# request actual response string from drive control server
get_response() {
  local STR="$1"
  local SRV='svcnat'
  local PRT='31337'
  echo -n "$STR" | /bin/nc -w 6 $SRV $PRT 2>/dev/null | tr '\0' '\n'
}

run_test() {
  let local GD=0,BA=0 # "Good Denied" and "Bad Allowed"
  gen_samples | while read REQ GB; do
    REXP=$(exp_response $REQ)
    RGET=$(get_response $REQ)
    if [ "$GB" == "OK" -a "$REXP" != "$RGET" ]; then
      let GD++
    fi
    if [ "$GB" == "EX" -a "$REXP" == "$RGET" ]; then
      let BA++
    fi
    echo "$GD $BA"
  done | tail -1
}

# calculate percentage of max.
pct_of() {
  local VAL="$1"
  local MAX="$2"
  echo "100 * $VAL / $MAX" | /bin/bc
}

# calculate score
calc_score() {
  local PGD="$1" # percent good dropped
  local PBA="$2" # percent bad allowed
  let local SCORE=100-PGD-PBA
  if ((SCORE>0)); then
    echo "$SCORE"
  else
    echo "0"
  fi
}

RES=($(run_test))
let PGD="$(pct_of ${RES[0]}  9)"
let PBA="$(pct_of ${RES[1]} 11)"
let SCORE=$(calc_score $PGD $PBA)
MSG="${PGD}pct valid req. denied; ${PBA}pct bad req. allowed; score=${SCORE}pct"

result=''

if ((SCORE>0)); then
  result="$result GradingCheck1: Success -- $MSG\n"
else
  result="$result GradingCheck1: Fail -- $MSG\n"
fi

if ((SCORE>20)); then
  result="$result GradingCheck2: Success -- pass\n"
else
  result="$result GradingCheck2: Fail -- fail\n"
fi

if ((SCORE>40)); then
  result="$result GradingCheck3: Success -- pass\n"
else
  result="$result GradingCheck3: Fail -- fail\n"
fi

if ((SCORE>60)); then
  result="$result GradingCheck4: Success -- pass\n"
else
  result="$result GradingCheck4: Fail -- fail\n"
fi

if ((SCORE>80)); then
  result="$result GradingCheck5: Success -- pass\n"
else
  result="$result GradingCheck5: Fail -- fail\n"
fi

printf "$result"
