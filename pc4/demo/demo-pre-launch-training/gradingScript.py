#!/usr/bin/python3

# Copyright 2023 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

import sys

def grade_challenge():
                
    act_code = open("./challenge/activation_code").read().strip()

    results = {}

    if sys.argv[1]:
        if sys.argv[1].strip() == act_code:
            results['GradingCheck1'] = "Success -- You found the final token!"
        else:
            results['GradingCheck1'] = "Failure -- Input does not match the activation code"
    else:
            results['GradingCheck1'] = "Failure -- Input does not match the activation code"

    for key, value in results.items():
        print(key, ' : ', value)


if __name__ == '__main__':
    grade_challenge()
