
# Copyright 2024 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

import os, sys, json, itertools, numpy
from pathlib import Path

adjacent_pins = {
'A':['A', '0', 'C', '2'],
'0':['A', '0', 'B', 'C', '2', 'D'],
'B':['0','B','1', '2', 'D', '3'],
'1':['B','1','D','3'],
'C':['A', '0','C', '2', 'E', '4'],
'2':['A', '0', 'B', 'C', '2', 'D', 'E', '4', 'F'],
'D':['0', 'B', '1', '2', 'D', '3', '4','F','5'],
'3':['B', '1', 'D', '3', 'F', '5'],
'E':['C', '2', 'E', '4', '6', '7'],
'4':['C', '2', 'D', 'E', '4', 'F', '6', '7', '8'],
'F':['2', 'D', '3', '4', 'F', '5', '7', '8', '9'],
'5':['D', '3', 'F', '5', '8', '9'],
'6':['E', '4', '6', '7'],
'7':['E', '4', 'F', '6', '7', '8'],
'8':['4', 'F', '5', '7', '8', '9'],
'9':['F', '5', '8', '9']
}

def create_combinations(pin, fp):
    # Below lambda expression loops through the numbers in the pin, grabs the entry for that number & its adjacent values, then maps those to a new key value 
    # that represents the index where that number appears in the pin. This allows for same numbers to be used multiple times without overwriting dict entries.
    pin_possibilities = dict((lambda x: (x,[pin[x],adjacent_pins[pin[x]]]) if pin[x] in list(adjacent_pins.keys()) else None)(key) for key in range(len(pin)) if pin[key] in list(adjacent_pins.keys()))
    poss_digit_list = list(v[1] for v in list(pin_possibilities.values()))

    lists = dict()
    for i, lst in enumerate(poss_digit_list):
        lists[f"list{i+1}"] = lst

    pin_combinations = list(itertools.product(*lists.values()))
    script_num_combo = len(pin_combinations)
    expected_answer = numpy.prod(list((len(adjacent_pins[p]) for p in pin)))
    
    try:
        with open(fp,'w+') as f:
            for p in pin_combinations:
                tmp = ''.join(p)
                f.write(tmp+'\n')
    except:
        print("error attempting to write to file")



def verify_args(pin, filepath):
    if (any(p not in list(adjacent_pins.keys()) for p in pin)):
        print("Pin must consist of hex characters only (0-F). Please verify pin and try again.")
        sys.exit()
    fp = Path(os.path.abspath(filepath))
    create_combinations(pin, fp)


if __name__ == '__main__':
    if len(sys.argv) != 3:
        print("2 arguments required. 1st is pin, 2nd is the full path to where you wish to write all pin possibilities.")
        sys.exit()
    verify_args(sys.argv[1], sys.argv[2])


