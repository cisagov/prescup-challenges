#!/bin/bash

# Copyright 2022 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

s1=$1  # pass in encrypted string
s2=$2  # pass in math variable 

plain=""
num=()
len=${#s1}

if (( $len < 1 )) || (( $len > 8 ))
then
	echo "The first argument must be a string consisting of 1 to 8 numbers"
	exit
fi

if  [[ "${s1}" =~ ^[a-zA-Z]+$ ]]              #checks that string only contains numbers
then
    echo "Please enter a string consisting of numbers only"
    exit
fi

if [ ${s1:0:1} == "-" ]
then
	echo "The first argument must be a postive string of numbers"
	exit
fi

for (( x=0;x< $len;x++ ))
do
    if [[ ${s1:$x:1} -gt 5 ]]
    then
        echo "All entered numbers must be five or less"
        exit
    fi
done

while [[ "$len" -gt 0 ]]            #runs until string is empty
do
    if [ ${#s1} = 1 ]
    then

        s1+="$s1"
    fi

    n1=${s1:0:1}        #assign first number to varaible n1
    n2=${s1: -1}        #assigns last number to variable n2

    n3=$((n1 + n2))

    plain+="$n3"
    num+="$n3"

    s1=${s1:1}
    s1=$(echo -n $s1 | head -c -1) 
 
    len=`expr $len - 2`
done

len1=${#num}

while [[ "$len1" -gt 0 ]]
do
    if [[ "$len1" -eq 1 ]]
    then
        num+="$num"
    fi

    n1="${num:0:1}"
    n2="${num:1:1}"

    if [ "$s2" == "*" ]		#need to escape when running with it
    then
        n4=$((n1*n2))
    elif [ "$s2" == "/" ]
    then
        if [[ $n2 -eq 0 ]]
        then
            n2=1
        fi
        n4=$((n1/n2))
    elif [ "$s2" == "+" ]
    then
        n4=$((n1+n2))
    elif [ "$s2" == "-" ]
    then
        n4=$((n1-n2))
        if [ "$n4" -lt 0 ]
        then
            n4=$((n4*-1))
        fi
    else
        echo "Unknown math character entered, please enter a *, /, + or - as the second argument."
        exit
    fi

    plain+="$n4"

    num=${num:2}

    len1=${#num}
done

echo $plain
