#!/bin/bash

# Copyright 2024 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.


#Get Infinity Names
mwnames=`vmtoolsd --cmd "info-get guestinfo.mwnames"` # 30 of these at random; SpyHex ViruCore MalwareX HackCraft DataFang DarkByte BugBlaze NetWorm RogueNet PhishEye ByteGrab CodeZap HackStomp RatPack SpyBlitz ByteBandit MalMelt ByteNinja HackHound CodeFury VirusLab ByteBite SpySquad HackPulse CodeChomp MalMine ByteBolt NetNuke BugByte SpySwift HackRush VirusVault ByteBash MalMaker CodeCrash NetNexus SpyStrike HackZone ByteBlitz MalMorph CodeCraze NetNinja BugBash SpySneak HackHive ByteBrawl VirusVoid MalMeld CodeCrest NetNimble 
mwarray=($mwnames)
cp /home/user/c03/stealer/mwlist.csv /home/user/c03/stealer/mw-list.csv

#Substitute Names
sed -i "s/MW001/${mwarray[0]}/g" /home/user/c03/stealer/mw-list.csv
sed -i "s/MW002/${mwarray[1]}/g" /home/user/c03/stealer/mw-list.csv
sed -i "s/MW003/${mwarray[2]}/g" /home/user/c03/stealer/mw-list.csv
sed -i "s/MW004/${mwarray[3]}/g" /home/user/c03/stealer/mw-list.csv
sed -i "s/MW005/${mwarray[4]}/g" /home/user/c03/stealer/mw-list.csv
sed -i "s/MW006/${mwarray[5]}/g" /home/user/c03/stealer/mw-list.csv
sed -i "s/MW007/${mwarray[6]}/g" /home/user/c03/stealer/mw-list.csv
sed -i "s/MW008/${mwarray[7]}/g" /home/user/c03/stealer/mw-list.csv
sed -i "s/MW009/${mwarray[8]}/g" /home/user/c03/stealer/mw-list.csv
sed -i "s/MW010/${mwarray[9]}/g" /home/user/c03/stealer/mw-list.csv
sed -i "s/MW011/${mwarray[10]}/g" /home/user/c03/stealer/mw-list.csv
sed -i "s/MW012/${mwarray[11]}/g" /home/user/c03/stealer/mw-list.csv
sed -i "s/MW013/${mwarray[12]}/g" /home/user/c03/stealer/mw-list.csv
sed -i "s/MW014/${mwarray[13]}/g" /home/user/c03/stealer/mw-list.csv
sed -i "s/MW015/${mwarray[14]}/g" /home/user/c03/stealer/mw-list.csv
sed -i "s/MW016/${mwarray[15]}/g" /home/user/c03/stealer/mw-list.csv
sed -i "s/MW017/${mwarray[16]}/g" /home/user/c03/stealer/mw-list.csv
sed -i "s/MW018/${mwarray[17]}/g" /home/user/c03/stealer/mw-list.csv
sed -i "s/MW019/${mwarray[18]}/g" /home/user/c03/stealer/mw-list.csv
sed -i "s/MW020/${mwarray[19]}/g" /home/user/c03/stealer/mw-list.csv
sed -i "s/MW021/${mwarray[20]}/g" /home/user/c03/stealer/mw-list.csv
sed -i "s/MW022/${mwarray[21]}/g" /home/user/c03/stealer/mw-list.csv
sed -i "s/MW023/${mwarray[22]}/g" /home/user/c03/stealer/mw-list.csv
sed -i "s/MW024/${mwarray[23]}/g" /home/user/c03/stealer/mw-list.csv
sed -i "s/MW025/${mwarray[24]}/g" /home/user/c03/stealer/mw-list.csv
sed -i "s/MW026/${mwarray[25]}/g" /home/user/c03/stealer/mw-list.csv
sed -i "s/MW027/${mwarray[26]}/g" /home/user/c03/stealer/mw-list.csv
sed -i "s/MW028/${mwarray[27]}/g" /home/user/c03/stealer/mw-list.csv
sed -i "s/MW029/${mwarray[28]}/g" /home/user/c03/stealer/mw-list.csv
sed -i "s/MW030/${mwarray[29]}/g" /home/user/c03/stealer/mw-list.csv

shuf /home/user/c03/stealer/mw-list.csv

cp /home/user/c03/stealer/mw-list.csv /home/user/challengeServer/hosted_files/mw-list.csv

#edit pcap times
date=`date +%s`
dateoffset=$(($date-1641571449-1800))
editcap -t $dateoffset /home/user/c03/stealer/traffic.pcapng
#cp /home/user/c03/stealer/traffic.pcapng /home/user/challengeServer/hosted_files/traffic.pcapng

nc -zv 10.4.4.4 22 > /dev/null

while [ $? -eq 1 ]
do
    echo "sleeping"
    sleep 5
    nc -zv 10.4.4.4 22 > /dev/null
done

#copy to sonion and import
scp /home/user/c03/stealer/traffic.pcapng so@10.4.4.4:/home/so/traffic.pcapng
ssh so@10.4.4.4 "echo 'tartans' | sudo -S so-import-pcap /home/so/traffic.pcapng"
