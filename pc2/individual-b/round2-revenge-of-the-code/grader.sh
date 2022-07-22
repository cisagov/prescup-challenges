#!/bin/bash

# Copyright 2022 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

> ./grading/rsa/rsaoutput.txt
> ./grading/rsa/results.txt
> ./grading/fibo/results.txt

token3="00kr0mtyyx0x"
token4="gp8ka8cejms9"
token5="yfc2w44rpky5"

if [ -f ./challenge/'problem 3'/rsa.py ]; then
    python ./challenge/'problem 3'/rsa.py ./grading/rsa/encrypted-1.txt > ./grading/rsa/rsaoutput.txt
    awk -i inplace '{ printf "%s", $0 }' ./grading/rsa/rsaoutput.txt
    if cmp -s -- "./grading/rsa/expected.txt" "./grading/rsa/rsaoutput.txt"; then
        echo "Your RSA script produced the expected output! You token is $token3!"
        
    else
        echo "Your RSA script did not produce the expected output"
        echo "Your script's output: " && cat ./grading/rsa/rsaoutput.txt
        echo "Expected: " && cat ./grading/rsa/expected.txt
    fi
else
    echo "The required ./challenge/problem 3/rsa.py file does not exist"
fi

if [ -f ./challenge/'problem 4'/optimize/src/functions.rs ]; then
    python ./grading/fibo/grade.py $token4 $token5
else
    echo "The required ./challenge/problem 4/optimize/src/functions.rs file does not exist"
fi
