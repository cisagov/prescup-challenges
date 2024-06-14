#!/bin/bash

# Copyright 2024 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.


html_dir=/var/www/html
names_file=/home/user/video-names.txt

sudo find "$html_dir" -type f -name "*.html" | while IFS= read -r file; do
  random_value=$(shuf -n 1 "$names_file")
  sed -i "s/d>video0/d>$random_value/g" "$file"
  random_value=$(shuf -n 1 "$names_file")
  sed -i "s/d>video1/d>$random_value/g" "$file"
  random_value=$(shuf -n 1 "$names_file")
  sed -i "s/d>video2/d>$random_value/g" "$file"
  random_value=$(shuf -n 1 "$names_file")
  sed -i "s/d>video3/d>$random_value/g" "$file"
  random_value=$(shuf -n 1 "$names_file")
  sed -i "s/d>video4/d>$random_value/g" "$file"
  random_value=$(shuf -n 1 "$names_file")
  sed -i "s/d>video5/d>$random_value/g" "$file"
  random_value=$(shuf -n 1 "$names_file")
  sed -i "s/d>video6/d>$random_value/g" "$file"
  random_value=$(shuf -n 1 "$names_file")
  sed -i "s/d>video7/d>$random_value/g" "$file"
  random_value=$(shuf -n 1 "$names_file")
  sed -i "s/d>video8/d>$random_value/g" "$file"
  random_value=$(shuf -n 1 "$names_file")
  sed -i "s/d>video9/d>$random_value/g" "$file"
done
  
