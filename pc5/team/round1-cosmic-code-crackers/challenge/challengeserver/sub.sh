#!/bin/bash

# Copyright 2024 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.


for file in name pass1 pass2
do
    # Define the input string
    input=$(cat $file)
    echo "Input string: $input"

    # Define the characters to substitute
    declare -A mapping=(
        ["a"]="q"
        ["b"]="w"
        ["c"]="e"
        ["d"]="r"
        ["e"]="t"
        ["f"]="y"
        ["g"]="u"
        ["h"]="i"
        ["i"]="o"
        ["j"]="p"
        ["k"]="a"
        ["l"]="s"
        ["m"]="d"
        ["n"]="f"
        ["o"]="g"
        ["p"]="h"
        ["q"]="j"
        ["r"]="k"
        ["s"]="l"
        ["t"]="z"
        ["u"]="x"
        ["v"]="c"
        ["w"]="v"
        ["x"]="b"
        ["y"]="n"
        ["z"]="m"
    )

    # Define a function to perform the substitution
    substitute() {
        local input="$1"
        local output=""
        for (( i=0; i<${#input}; i++ )); do
            char="${input:$i:1}"
            if [[ ${mapping[$char]+_} ]]; then
                output+="${mapping[$char]}"
            else
                output+="$char"
            fi
        done
        echo "$output"
    }

    # Call the substituton
    output=$(substitute "$input")
    echo "Output string: $output"

    # Write the output to a file
    echo -n "$output" > $file
done
