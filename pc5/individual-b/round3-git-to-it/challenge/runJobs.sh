#!/bin/bash

# Copyright 2024 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

i=36
while true; do
    sleep 60
    curl -k --request POST "https://gitlab.awkward.org/api/v4/projects/2/jobs/$i/retry" --header "PRIVATE-TOKEN:glpat-6BBynG8gyiVPnm-Nh18X"
    ((i+=1))
done
