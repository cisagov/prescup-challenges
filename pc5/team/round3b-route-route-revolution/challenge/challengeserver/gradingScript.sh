#!/bin/bash

# Copyright 2024 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.


# Initialize result variable
result="$result "

# Perform traceroute on ens32
ip -6 route add 2001:0db8:abcd:2222::/64 via 2001:0db8:abcd:1111::1 dev ens32

traceroute6 -n -q 10 -i ens32 -w 1 2001:0db8:abcd:2222::1000 > /home/user/challengeServer/hosted_files/GradingCheck1-Output.txt

if traceroute6 -n -q 10 -i ens32 -w 1 2001:0db8:abcd:2222::1000 >/dev/null 2>&1; then
    hops1=$(traceroute6 -n -i ens32 -q 10 -w 1 2001:0db8:abcd:2222::1000 | awk 'END {print $1}')
    echo $hops1
else
    result="$result GradingCheck1: Failure -- The traceroute from network A to network B could not be established. \n"
fi

# Perform traceroute on ens34
ip -6 route add 2001:0db8:abcd:4444::/64 via 2001:0db8:abcd:3333::1 dev ens34

traceroute6 -n -q 10 -i ens34 -w 1 2001:0db8:abcd:4444::1000 > /home/user/challengeServer/hosted_files/GradingCheck2-Output.txt
if traceroute6 -n -i ens34 -q 10 -w 1 2001:0db8:abcd:4444::1000 >/dev/null 2>&1; then
    hops2=$(traceroute6 -n -i ens34 -q 10 -w 1 2001:0db8:abcd:4444::1000 | awk 'END {print $1}')
    echo $hops2
else
    result="$result GradingCheck2: Failure -- The traceroute from network Y to network X could not be established. \n"
fi

if [ "$hops1" -le 4 ]; then
    result="$result GradingCheck1: Success -- You have optimized the friendly route. \n"
else
    result="$result GradingCheck1: Failure -- You have not optimized the friendly route. The friendly route currently takes $hops1 hops. \n"
fi    
    
if [ "$hops1" -le 4 ] && [ "$hops2" -ge 7 ]; then
    result="$result GradingCheck2: Success -- You have deoptimized the enemy route without breaking the optimized friendly route. \n"
else
    result="$result GradingCheck2: Failure -- The friendly route currently takes $hops1 while the enemy route currently takes $hops2 hops. \n"
fi

# Print the final result
printf "$result"


