#!/bin/bash

service ssh start
sleep 5
sed -i "s/TOKEN{log_analysis}/$(curl -s flagserver/token7.txt)/g" /logsim.py
python3 /logsim.py 
rm /logsim.py

sleep infinity