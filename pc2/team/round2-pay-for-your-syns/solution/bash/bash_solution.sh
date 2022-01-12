#!/bin/bash

# Copyright 2022 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

dec=$1  # pass in encrypted string
len=${#dec}

function add (){
    res=`expr $1 + $2`
    echo $res
}

function sub (){
    res=`expr $1 - $2`
    if [[ "$res" -lt 0 ]]
    then
        res=`expr $res \* -1`
    fi
    echo $res
}

function div (){
    if [[ $2 -eq 0 ]]
    then
        res=`expr $1 / 1`
    else
        res=`expr $1 / $2`
    fi
    echo $res
}

function mul (){
    res=`expr $1 \* $2`
    
    echo $res
}

declare -A FUNC           #associative array of functions
FUNC[0]=add
FUNC[1]=sub
FUNC[2]=mul
FUNC[3]=div

declare -A strings        #associative array of string variables
strings[addStr]=""
strings[subStr]=""
strings[mulStr]=""
strings[divStr]=""


function strMaker (){                      # passes first matched number in string, pos of it, and function use
    i=`expr $3 + 2`                            # new index to start grabbing next two numbers to do arthimetic on
    nextLet=$1                        # new matchIndex
    nextVal1=${dec:$i:1}
    nextVal2=${dec:$i+1:1}

    last=0
    stringsFunc="${FUNC[$2]}Str"            #addStr, subStr, etc.
    currSize=${#strings[$stringsFunc]}      #gets size of current array value
    currStr=${strings[$stringsFunc]} 
    next="${dec:$i+1}"                      #string left to process after 1  character: check if theres 1 character left before match.
    next=$(echo -n $next | head -c -1)      # if 1 character left, then the end of string should match minus last number to be added
    next2="${dec:$i+1}"
    next2=$(echo -n $next2 | head -c -2) 

    if [ "$currStr" == "$next" ] || [ "$currStr" == "$next2" ]
    then
        nextVal2=$nextVal1              
        last=1                              #checker, if this runs then this is last letter to run against function.
    elif [ "$currStr" == "${dec:$i}" ]
    then
        return
    elif [ -z ${dec:$i:1} ] && [ "$currStr" == "0${dec:$i}" ] #leading zero issue
    then
        return
    fi


    if [[ -z "$nextVal1" ]] || [[ -z "$nextVal2" ]]
    then
        return
    fi

    if [[ `${FUNC[$2]} $nextVal1 $nextVal2` -lt 10 ]]      
    then
        if [[ `${FUNC[$2]} $nextVal1 $nextVal2` -eq ${dec:$nextLet:1} ]]
        then
            i=`expr $3 + 2`
            num=`${FUNC[$2]} $nextVal1 $nextVal2`
            strings["${FUNC[$2]}Str"]+="$num"
            nextLet=`expr $nextLet + 1`
            if [ $last == 1 ]
            then
                return                          # make sure it doesnt go past end of string
            fi
            strMaker "$nextLet" "$2" "$i"       # $1=matched number in string, $2=i is location of first match, $3=function used, $4=index of 2 numbers to do math too
        fi
    elif [[ `${FUNC[$2]} $nextVal1 $nextVal2` -gt 9 ]]
    then
        if [[ `${FUNC[$2]} $nextVal1 $nextVal2` -eq ${dec:$nextLet:2} ]]
        then
            i=`expr $3 + 2`
            num=`${FUNC[$2]} $nextVal1 $nextVal2`
            strings["${FUNC[$2]}Str"]+="$num"
            nextLet=`expr $nextLet + 2`
            if [ $last == 1 ]
            then
                return                          # make sure it doesnt go past end of string
            fi
            strMaker "$nextLet" "$2" "$i"        # $1=matched number in string, $2=i is location of first match, $3=function used, $4=index of 2 numbers to do math too
        fi
    fi
}

function check (){                      # check for first match with each math variable
    i=$2     #first num location to grab for math equation
    matchIndex=$1
    v1=${dec:$i:1}
    v2=${dec:$i+1:1}

    if [ -z "$v2" ] || [ -z "${dec:$matchIndex:1}" ]
    then
        return
    fi

    for f in "${!FUNC[@]}" 
    do
        if [[ `${FUNC[$f]} $v1 $v2` -lt 10 ]]      # test and see if you need $f or f in FUNC call
        then
            if [[ `${FUNC[$f]} $v1 $v2` -eq ${dec:$matchIndex:1} ]]
            then
                i=$2
                num=`${FUNC[$f]} $v1 $v2`
                strings["${FUNC[$f]}Str"]+="$num"
                nextLet=`expr $matchIndex + 1`
                strMaker "$nextLet" "$f" "$i"      # $1=index of matched value in string, $2=i is function used, $3= index of numbers used for math equation, $4 is length of match (>9 or <10)
            
            fi
        elif [[ `${FUNC[$f]} $v1 $v2` -gt 9 ]]
        then
            if [[ `${FUNC[$f]} $v1 $v2` -eq ${dec:$matchIndex:2} ]]
            then
                i=$2
                num=`${FUNC[$f]} $v1 $v2`
                strings["${FUNC[$f]}Str"]+="$num"
                nextLet=`expr $matchIndex + 2`
                strMaker "$nextLet" "$f" "$i" 
            fi
        fi
    done
}

declare -A longest
longest[addStr]=""
longest[subStr]=""
longest[mulStr]=""
longest[divStr]=""

for startLoc in `seq 0 2 $len`
do
    ma=`expr $startLoc + 2`
    for maIndex in `seq $ma $len`
    do
        check "$maIndex" "$startLoc"
        #echo "match index is:$maIndex start location is $startLoc, addstr = ${strings[addStr]}"
        #echo "match index is:$maIndex start location is $startLoc, substr = ${strings[subStr]}"
        #echo "match index is:$maIndex start location is $startLoc, mulstr = ${strings[mulStr]}"
        #echo "match index is:$maIndex start location is $startLoc, divstr = ${strings[divStr]}"
        nxt="${strings[addStr]}"
        cur="${longest[addStr]}"
        if [[ ${#nxt} > ${#cur} ]]
        then
            longest[addStr]=$nxt
        fi
        
        nxt="${strings[subStr]}"
        cur="${longest[subStr]}"
        if [[ ${#nxt} -gt ${#cur} ]]
        then
            longest[subStr]=$nxt
        fi
        
        nxt="${strings[divStr]}"
        cur="${longest[divStr]}"
        if [[ ${#nxt} -gt ${#cur} ]]
        then
            longest[divStr]=$nxt
        fi
        
        nxt="${strings[mulStr]}"
        cur="${longest[mulStr]}"
        if [[ ${#nxt} -gt ${#cur} ]]
        then
            longest[mulStr]=$nxt
        fi

        strings[addStr]=""
        strings[subStr]=""
        strings[mulStr]=""
        strings[divStr]=""

    done
done


for ans in "${!longest[@]}"
do
    echo "String type: $ans"
    echo "String: ${longest[$ans]}"
done

