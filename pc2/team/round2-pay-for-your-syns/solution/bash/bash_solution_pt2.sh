#!/bin/bash

# Copyright 2022 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

dec=$1  # pass in 1st part of decrypted string found after other script
len=${#dec}

extra=$dec
declare -A numPairs
declare -A doubNumPairs 
declare -a strArr
declare -a newArray
declare -A tempArr
pairs=""
matchIndex=0
matchIndex1=0

function findPairs (){                   #pass number to check pairs for
    indAns=""
    pairAns=""
    for a in {0..5}
    do
        for b in {0..5}
        do
            if [[ $(( "$a" + "$b" )) -eq $1 ]]
            then
                if [[ ${#1} -eq 1 ]]
                then
                    ans+="$a,$b "
                    indAns+="$a,$b $b,$a "
                    pairs="$ans"
                elif [[ ${#1} -eq 2 ]]
                then
                    ans1+="$a,$b "
                    pairAns+="$a,$b "
                    doubPairs="$ans1"           #record two number passed in and pairs of it
                    #echo "$pairAns and $doubPairs"
                fi
            fi
        done
    done
    if [[ -n ${indAns} ]]
    then
        numPairs["$matchIndex"]+="$indAns"
        matchIndex=`expr $matchIndex + 1`
    fi

    if [[ -n ${pairAns} ]]
    then
        doubNumPairs["$matchIndex1"]+="$pairAns"
        matchIndex1=`expr $matchIndex1 + 1`
    fi
    
}

function numChecker (){         #first arg is place in string to grab index
    num=${dec:$1:2}
    if [[ -z "${num:0:1}" ]]
    then
        return
    elif [[ -z "${num:1:1}" ]]
    then
        findPairs ${num:0:1}
        return    
    elif [[ "$num" -gt 18 ]]
    then
        findPairs ${num:0:1}
        index=`expr $1 + 1`
        if [[ $index -gt ${#dec} ]]
        then
            return
        fi
        numChecker $index
    elif [[ "$num" -le 18 ]]
    then 
        for x in {1..2} 
        do
            curStr=${dec:$1:$x}
            if [[ -z $curStr ]]
            then
                return
            fi
            if [[ ${#curStr} -eq 1 ]]
            then
                findPairs $curStr
                index=`expr $index + 1`
                if [[ $index -gt ${#dec} ]]
                then
                    return
                fi
                numChecker $index
            elif [[ ${#curStr} -eq 2 ]]
            then
                findPairs $curStr
                index=`expr $index + 2`
                if [[ $index -gt ${#dec} ]]
                then
                    return
                fi
                numChecker $index
            fi
        done
    fi
}

function popArr (){
    if [[ $1 -eq `expr ${#numPairs[@]} - 1` ]]
    then
        for (( g=0; g<"${#numPairs[$1]}"; g+=4 ))
        do
            h=${numPairs[$1]:$g:1}
            i=${numPairs[$1]:$g+2:1}
            insert2="$h$i"
            halfCurSize=`expr ${#2} / 2`
            beg=${2:0:$halfCurSize}
            end=${2:$halfCurSize}
            stringMaker="$beg$insert2$end\n"
            strArr+="$stringMaker"
            stringMaker="$2"
        done
    else
        for (( j=0; j<"${#numPairs[$1]}"; j+=4 ))
        do
            e=${numPairs[$1]:$j:1}
            f=${numPairs[$1]:$j+2:1}
            insert="$e$f"
            halfCurSize=`expr ${#2} / 2`
            beg=${2:0:$halfCurSize}
            end=${2:$halfCurSize}
            stringMaker="$beg$insert$end"
            index=`expr $1 + 1`

            if [[ -z ${numPairs[$1]} ]]
            then
                return
            fi
            popArr $index $stringMaker
            index=$1
        done
    fi
}

function strMaker (){
    if [[ $1 -eq `expr ${#numPairs[@]} - 1` ]]                             #check size, not contents cause numbers could be the same
    then
        for (( g=0; g<"${#numPairs[$1]}"; g+=4 ))
        do
            h=${numPairs[$1]:$g:1}
            i=${numPairs[$1]:$g+2:1}
            insert2="$h$i"
            halfCurSize=`expr ${#2} / 2`
            beg=${2:0:1}
            end=${2:1}
            stringMaker="$beg$insert2$end\n"
            strArr+="$stringMaker"
            stringMaker="$2"
        done
    else  
        for (( z=0; z<"${#numPairs[$1]}"; z+=4 ))                          # call function to loop and create strings
        do   
            c=${numPairs[$1]:$z:1}
            d=${numPairs[$1]:$z+2:1}
            insert3="$c$d"
            halfCurSize=`expr ${#2} / 2`
            beg=${2:0:$halfCurSize}
            end=${2:$halfCurSize}
            stringMaker="$beg$insert3$end"
            index=`expr $1 + 1`

            popArr $index $stringMaker 
            index=$1
        done
        fi
}

# for all single character possibilities
function singArrMaker () {
    size=`echo ${#numPairs[0]}`
    size=`expr $size - 1`
    for (( x=0 ; x < $size ; x+=4 ))              # gets the size of the value of the first spot in array to iterate through, 
    do
        firstStr=`echo ${numPairs[0]}`
        frstLet="${firstStr:$x:1}"
        lastLet="${firstStr:$x+2:1}"
        stringMaker="$frstLet$lastLet"                            #starts string creation with first pair from starting number

        strMaker 1 $stringMaker
    done

    #echo -e ${strArr[@]}
}

function clearArr () {
    unset $1
    declare -A $1
}



# for all double character possibilities
function doubSubstitute () {
    for (( x=0; x < ${#doubNumPairs[@]}; x++ ))
    do
        for ((y=0; y < ${#dec}; y++ ))
        do
            v1=${doubNumPairs[$x]:0:1}
            v2=${doubNumPairs[$x]:2:1}
            val=`expr $v1 + $v2`

            if [[ -z ${dec:$y:1} ]] || [[ -z ${dec:$y+1} ]]
            then
                break
            else
                decV=${dec:$y:2}
            fi

            if [[ $val -eq $decV ]]
            then
                for (( z=0; z < ${#numPairs[@]}; z++))
                do
                    p=`expr $z + 1`
                    val1=${numPairs[$z]:0:1}
                    val2=${numPairs[$z]:2:1}
                    frstStr=`expr $val1 + $val2`
                    val3=${numPairs[$p]:0:1}
                    val4=${numPairs[$p]:2:1}
                    secStr=`expr $val3 + $val4`
                    strChk="$frstStr$secStr"
                    
                    if [[ $strChk -eq $decV ]]
                    then
                        temp=( "${doubNumPairs[$x]}" )
                        numPairs[$z]=$temp
                        unset numPairs[$p]
 

                        m=0
                        for val in ${!numPairs[@]}
                        do
                            if [[ "${numPairs[$val]}" == "" ]]
                            then
                                continue
                            else
                                newArray[$m]=${numPairs[$val]}
                                m=`expr $m + 1`
                            fi
                        done
                        
                        clearArr numPairs
                        unset numPairs
                        declare -A numPairs

                        n=0
                        for va in ${!newArray[@]}
                        do
                            if [[ "${newArray[$va]}" == "" ]]
                            then
                                continue
                            else
                                numPairs[$n]=${newArray[$va]}
                                n=`expr $n + 1`
                            fi
                        done

                        for (( q=0;q<${#numPairs[@]};q++ ))
                        do
                            tempArr[$q]=${numPairs[$q]}
                        done

                        clearArr newArray
                        unset newArray
                        declare -A newArray
                        break 2
                        
                    fi
                done
            fi
        done
    done
}

function doubArrMaker (){
    tmp=0
    for val2 in ${!tempArr[@]}
    do
        numPairs[$tmp]=${tempArr[$val2]}
        tmp=`expr $tmp + 1`
    done
    size=${#numPairs[0]}
    size=`expr $size - 1`

    for (( x=0 ; x < $size ; x+=4 ))              # gets the size of the value of the first spot in array to iterate through, 
    do
        frstLet="${numPairs[0]:$x:1}"
        lastLet="${numPairs[0]:$x+2:1}"                            #starts string creation with first pair from starting number
        stringMaker="$frstLet$lastLet"                            #starts string creation with first pair from starting number

        strMaker 1 $stringMaker
    done

    echo -e ${strArr[@]}
}

index=0
numChecker $index
echo "List of pairs for all 1 character numbers in string: $pairs"
echo "List of pairs for all 2 character numbers in string: $doubPairs"

singArrMaker
doubSubstitute
doubArrMaker
