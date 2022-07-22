#!/bin/bash

# Copyright 2022 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

# array size is equal to # of args x2, and put together at end when all values and indexs are counter for

s1=$1  # pass in first arg string
s2=$2  # pass in second arg string 
s3=$3  # etc
s4=$4
s5=$5  # 5 args max

encrypt=()

declare -A pos
pos=([0]=0 [1]=1 [2]=2 [3]=3 [4]=4 [5]=5 [6]=6 [7]=7 [8]=8 [9]=9)

argAmt=$#
if [ "$argAmt" -gt 5 ]
then
    echo "Too many arguments passed"
    exit
fi

for s in "$@"
do
    l=${s:0:1}   # gets special character, not sure if all of them need to be literal
    d1=${s:1:1}  # Gets first digit
    d2=${s:2:1}  # Gets second digit, cant be bigger than number of arguments x 2. only two character get added to array per argument
    d3=${s:3:1}  # Gets third digit
    d1Num="$d1"  # for math below

    if [ "$l" = "!" ]  # loop reads special character and substitutes value
    then
        l=5
    elif [ "$l" = "?" ]
    then
        l=3
    elif [ "$l" = "#" ]
    then
        l=1
    elif [ "$l" = "@" ]
    then
        l=0
    elif [ "$l" = "<" ]
    then
        l=8
    elif [ "$l" = ">" ]
    then
        l=2
    elif [ "$l" = "$" ]
    then
        l=4
    elif [ "$l" = "%" ]
    then
        l=9
    elif [ "$l" = "&" ]
    then
        l=7
    elif [ "$l" = "*" ]
    then
        l=6
    else
        echo "you didnt follow the right format 1"
	exit
    fi

    if [ "$d1" = 0 ]  # loop reads first digit and substitutes special character
    then
        d1="$"
    elif [ "$d1" = 1 ]
    then
        d1="%"
    elif [ "$d1" = 2 ]
    then
        d1="<"
    elif [ "$d1" = 3 ]
    then
        d1="&"
    elif [ "$d1" = 4 ]
    then
        d1="@"
    elif [ "$d1" = 5 ]
    then
        d1="*"
    elif [ "$d1" = 6 ]
    then
        d1="!"
    elif [ "$d1" = 7 ]
    then
        d1="?"
    elif [ "$d1" = 8 ]
    then
        d1=">"
    elif [ "$d1" = 9 ]
    then
        d1="#"
    else
        echo "you didnt follow the right format 2"
	exit
    fi
  

    m=$(( l / d1Num ))
    m=$(( m * d3 ))
    m=$(( m + d2 ))
    
    size="${#m}"         # get amt of numbers in number
    size=$Size-1
    finNum=${m:size:1}
    finLet=''

    if [ "$finNum" = 0 ]       #based on final number, assign a letter to be put in encrypted array
    then
        finLet="o"
    elif [ "$finNum" = 1 ]
    then
        finLet="l"
    elif [ "$finNum" = 2 ]
    then
        finLet="v"
    elif [ "$finNum" = 3 ]
    then
        finLet="e"
    elif [ "$finNum" = 4 ]
    then
        finLet="f"
    elif [ "$finNum" = 5 ]
    then
        finLet="w"
    elif [ "$finNum" = 6 ]
    then
        finLet="p"
    elif [ "$finNum" = 7 ]
    then
        finLet="t"
    elif [ "$finNum" = 8 ]
    then
        finLet="d"
    elif [ "$finNum" = 9 ]
    then
        finLet="q"
    else
        echo "Mistakes were made"
		exit
    fi

    #finLet, special character manipulated, insert at position represented by d4
    #d1, first number converted based on mapping, insert at position represented by d2

    for ((i=0; i<10; i++ ))     #loops, if {"$d2"} equals value at certain index, replace the value at that index with finLet value. Also user must realize that all arguements must have different indexs used
    do
	if [[ $d3 == ${pos["$i"]} ]] && [[ ${pos["$i"]} == $i ]]    # if values are equal and it does have its original value, replace it
        then
           pos[$i]=$finLet
	fi

	if [[ $d2 == ${pos["$i"]} ]] && [[ ${pos["$i"]} == $i ]]     # if correct inserts converted d1 into array
	then
	    pos[$i]=$d1
	fi
    done
done
# method to insert the position variables (p1, p2) in array since itll be in order from past methods

for ((j=0; j<10; j++))
do
	encrypt[$j]="${pos["$j"]}"
done

echo "${encrypt[*]}"

