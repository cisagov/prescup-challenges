#!/usr/bin/python3

# Copyright 2022 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

import logging
import subprocess
import sys


print(f"Grading script got args {sys.argv}")
results = {"GradingCheck1": "Fail", "GradingCheck2": "Fail", "GradingCheck3": "Fail", "GradingCheck4": "Fail", "GradingCheck5": "Fail", "GradingCheck6": "Fail", "GradingCheck7": "Fail", "GradingCheck8": "Fail", "GradingCheck9": "Fail",}

entered_names = sys.argv[1].lower().replace(" ", "").split(",")
print(f"Entered Names - {entered_names}")

correct_names = ["brittney.lewis.machinenatural", "christopher.garcia.thatanswer", "erin.garza.tvsell", "nathan.tyler.yetherself", "carrie.rodriguez.starif", "david.lee.statementsave", "joseph.woods.rangesimilar", "christopher.boyd.smilecompare", "benjamin.brown.himprice"]

correct_results = []
incorrect_results = []

for name in entered_names:
    name = name.strip()
    if len(name) > 0:
        for cname in correct_names:
            if cname in name:
                correct_results.append(name)
                break
        
        if name not in correct_results:
            incorrect_results.append(name)

totalCorrect = len(correct_results) - len(incorrect_results)

if totalCorrect < 0:
    totalCorrect = 0
    
#print(totalCorrect)
    
for x in range(totalCorrect):
    results["GradingCheck" + str(x+1)] = "Success"
    
#print(results)
			
for key, value in results.items():
    print(key, ' : ', value)
			    
exit(0)

