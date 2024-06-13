#!/bin/bash

# Copyright 2024 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.


date1=`date -d "1 days ago" +"%a"` 
date2=`date -d "2 days ago" +"%a"` 
date3=`date -d "3 days ago" +"%a"` 
date4=`date -d "4 days ago" +"%a"` 
date5=`date -d "5 days ago" +"%a"`

day1dm=`date -d "1 days ago" +"%d %b"`
day2dm=`date -d "2 days ago" +"%d %b"`
day3dm=`date -d "3 days ago" +"%d %b"`
day4dm=`date -d "4 days ago" +"%d %b"`
day5dm=`date -d "5 days ago" +"%d %b"`

day1md=`date -d "1 days ago" +"%b %d"`
day2md=`date -d "2 days ago" +"%b %d"`
day3md=`date -d "3 days ago" +"%b %d"`
day4md=`date -d "4 days ago" +"%b %d"`
day5md=`date -d "5 days ago" +"%b %d"`

day1ymd=`date -d "1 days ago" +"%Y%m%d"`
day2ymd=`date -d "2 days ago" +"%Y%m%d"`
day3ymd=`date -d "3 days ago" +"%Y%m%d"`
day4ymd=`date -d "4 days ago" +"%Y%m%d"`
day5ymd=`date -d "5 days ago" +"%Y%m%d"`

rm -f test.txt

cp gold.txt working.txt

sed -i s/1DATEAGO/$date1/g working.txt
sed -i s/2DATEAGO/$date2/g working.txt
sed -i s/3DATEAGO/$date3/g working.txt
sed -i s/4DATEAGO/$date4/g working.txt
sed -i s/5DATEAGO/$date5/g working.txt

sed -i "s/10 Dec/$day5dm/g" working.txt
sed -i "s/11 Dec/$day4dm/g" working.txt
sed -i "s/12 Dec/$day3dm/g" working.txt
sed -i "s/13 Dec/$day2dm/g" working.txt
sed -i "s/14 Dec/$day1dm/g" working.txt

sed -i "s/Dec 10/$day5md/g" working.txt
sed -i "s/Dec 11/$day4md/g" working.txt
sed -i "s/Dec 12/$day3md/g" working.txt
sed -i "s/Dec 13/$day2md/g" working.txt
sed -i "s/Dec 14/$day1md/g" working.txt

sed -i "s/20231210/$day5ymd/g" working.txt
sed -i "s/20231211/$day4ymd/g" working.txt
sed -i "s/20231212/$day3ymd/g" working.txt
sed -i "s/20231213/$day2ymd/g" working.txt
sed -i "s/20231214/$day1ymd/g" working.txt
