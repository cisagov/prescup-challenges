#!/bin/bash

curl https://raw.githubusercontent.com/devmece/pcap2frame/master/pcap2frame.py | sed 2,31d | sed 15,23d | sed 20,28d | sed 21,24d | sed 55,59d | sed 88,96d | sed 92d | sed 96,99d | sed 98,107d | sed 5,7d | sed 88d > example_solution.py


sed -i '' "s/python/python3/g" example_solution.py
sed -i '' "2i\\
\\
" example_solution.py
sed -i '' "s/from\ StringIO/from\ io/g" example_solution.py
sed -i '' "6i\\
from multiprocessing import Pool\\
import numpy as np\\
import csv,argparse,time,os,sys,pandas\\
\\
\# lambdas for date stuff\\
" example_solution.py
sed -i '' "15i\\
\# fields of interest for each protocol -- will be dataframe column names later\\
" example_solution.py
sed -i '' "s/'data','date'.*/'data',\ 'stream',\ 'date','time']/g" example_solution.py
sed -i '' "21i\\
\# command to use in tshark to process pcap files\\
" example_solution.py
sed -i '' "s/-e\ data\ tcp.*/-e data -e tcp.stream tcp and not \"(ipv6 or icmp)\" > %s'/g" example_solution.py
sed -i '' "27i\\
\\
\# process a pcap file with tshark\\
\# This is saved to a temp file that will be used to create the csv later\\
" example_solution.py
sed -i '' "s/print\ dat(),\"Processing:\",pcap/print(\ dat(),\"Processing:\",pcap)/g" example_solution.py
sed -i '' "41i\\
\\
\# transform a tshark output file to a csv that can be used with pandas\\
" example_solution.py
sed -i '' "s/def\ CreateCsv.*/def\ CreateCsv(outputFileName,protocol):/g" example_solution.py
sed -i '' "s/\# print\ dat(),\"Creating.*/print(\ dat(),\"Creating:\",csvFileName)/g" example_solution.py
sed -i '' "s/print\ \"There.*/print(\"There is a problem processing PCAP. If the error occured while processing UDP packets, try upgrading tshark.\")/g" example_solution.py
sed -i '' "97i\\
\\
\# crate pandasDataFrame from a pcap csv\\
" example_solution.py
sed -i '' "s/def\ CreateData.*/def\ CreateDataFrame(csvFileName,protocol):/g" example_solution.py
sed -i '' "103i\\
\ \ \ \ \ \ \ \ pDataframe.to_pickle(\"capture1.pkl\")\\
\ \ \ \ \ \ \ \ return pDataframe\\
\\
\\
def findRegularConnections(pcap_file):\\
\ \ \ \ \# if a pickle exists, (This pcap was already processed once), then read the pickle instead of processing again\\
\ \ \ \ if os.path.exists('capture1.pkl'):\\
\ \ \ \ \ \ \ \ df = pandas.read_pickle('capture1.pkl')\\
\ \ \ \ else:\\
\ \ \ \ \ \ \ \ \# go from pcap to dataframe\\
\ \ \ \ \ \ \ \ outputFileName = ExtractPcapData(pcap_file,\"tcp\")\\
\ \ \ \ \ \ \ \ csvFileName = CreateCsv(outputFileName,\"tcp\")\\
\ \ \ \ \ \ \ \ df = CreateDataFrame(csvFileName,\"tcp\")\\
\\    
" example_solution.py
sed -i '' "117i\\
\ \ \ \ \# get the time in a standard format for calculations (cant process if time is a string) \\
\ \ \ \ df['time'] = pandas.to_datetime(df['time'])\\
\\
\ \ \ \ \# group results by source / dest IP\\
\ \ \ \ \# this makes it easier to calc the time between connections to the same host\\
\ \ \ \ groups = df.groupby(['source_ip', 'dest_ip'])\\
\\
\ \ \ \ \# for each source/dest IP group, print the differences between each connection\\
\ \ \ \ for name, group in groups:\\
\ \ \ \ \ \ \ \ print(name)\\
\ \ \ \ \ \ \ \ diff = group['time'].diff()\\
\ \ \ \ \ \ \ \ diff = diff / np.timedelta64(1, 's') # gets differences in seconds\\
\ \ \ \ \ \ \ \ diff = diff[diff >= 60] # gets differences in seconds when seconds is >= 60 -- this filters out packets that are part of the same connection (have very very small time differences)\\
\ \ \ \ \ \ \ \ print(diff) # this is a list of all connections >= 60 between each\\
\\
" example_solution.py        
sed -i '' "134i\\
\ \ \ \ \# parse cmdline args\\
" example_solution.py
sed -i '' "s/,required=True//g" example_solution.py
sed -i '' "137i\\
\ \ \ \ aParser.add_argument(\"--dir\",help=\"directory of pcaps to process\")\\
" example_solution.py
sed -i '' "140i\\
\ \ \ \ directory = args.dir\\
\\
\ \ \ \ if pcap:\\
\ \ \ \ \ \ \ \ findRegularConnections(pcap)\\
\\
\\
\\
" example_solution.py
