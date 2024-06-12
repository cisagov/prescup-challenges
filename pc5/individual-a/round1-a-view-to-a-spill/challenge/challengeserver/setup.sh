#!/bin/bash

# Copyright 2024 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.


t1=`vmtoolsd --cmd "info-get guestinfo.t1"` # a 12 character hex string, e.g. 12ab34cd56ef
t2=`vmtoolsd --cmd "info-get guestinfo.t2"` # a 12 character hex string, e.g. 12ab34cd56ef
t3=`vmtoolsd --cmd "info-get guestinfo.t3"` # a 12 character hex string, e.g. 12ab34cd56ef
dev=`vmtoolsd --cmd "info-get guestinfo.devnum"` # an integer between 250 and 480
serial=$(echo VIGEY5000-4203-91-$dev)
serialbase=$(echo -n "$serial" | base64)
webdir="${serialbase%%=*}"


#adjust device list
sed -i "s/###/$dev/g" /home/user/c09/device-list.txt
cp /home/user/c09/device-list.txt /home/user/challengeServer/hosted_files/

#modify video file name
index=`vmtoolsd --cmd "info-get guestinfo.index"` # an integer between 1 and 10
if [ "$index" -ge 6 ]; then
    result=$((index - 5))
else
    result=$index
fi

numb=$((index - 1))

#modify transmission log dates
current_date=$(date +%Y-%m-%d)
pdate7=$(date -d "$current_date - 7 days" +%y-%m-%d)
pdate6=$(date -d "$current_date - 6 days" +%y-%m-%d)
pdate5=$(date -d "$current_date - 5 days" +%y-%m-%d)
pdate4=$(date -d "$current_date - 4 days" +%y-%m-%d)
pdate3=$(date -d "$current_date - 3 days" +%y-%m-%d)
fdate7=$(date -d "$pdate7" +"%B %dth, %Y")
fdate6=$(date -d "$pdate6" +"%B %dth, %Y")
fdate5=$(date -d "$pdate5" +"%B %dth, %Y")
fdate4=$(date -d "$pdate4" +"%B %dth, %Y")
fdate3=$(date -d "$pdate3" +"%B %dth, %Y")

sed -i "s/May 9th, 2023/$fdate7/g" /home/user/c09/transmission-log.txt
sed -i "s/May 10th, 2023/$fdate6/g" /home/user/c09/transmission-log.txt
sed -i "s/May 11th, 2023/$fdate5/g" /home/user/c09/transmission-log.txt
sed -i "s/May 12th, 2023/$fdate4/g" /home/user/c09/transmission-log.txt
sed -i "s/May 13th, 2023/$fdate3/g" /home/user/c09/transmission-log.txt
sed -i "s/May9th,2023/$fdate7/g" /home/user/c09/video-names.txt
sed -i "s/May10th,2023/$fdate6/g" /home/user/c09/video-names.txt
sed -i "s/May11th,2023/$fdate5/g" /home/user/c09/video-names.txt
sed -i "s/May12th,2023/$fdate4/g" /home/user/c09/video-names.txt
sed -i "s/May13th,2023/$fdate3/g" /home/user/c09/video-names.txt

case $result in
    1)
        newname="$(echo "$fdate7" | sed 's/ //g')"-"16:34:10"
        ;;
    2)
        newname="$(echo "$fdate6" | sed 's/ //g')"-"07:15:42"
        ;;
    3)
        newname="$(echo "$fdate5" | sed 's/ //g')"-"08:05:17"
        ;;
    4)
        newname="$(echo "$fdate4" | sed 's/ //g')"-"08:15:20"
        ;;
    5)
        newname="$(echo "$fdate3" | sed 's/ //g')"-"08:05:15"
        ;;
    *)
        echo "Result not found"
        exit 1
        ;;
esac

cp /home/user/c09/$t2.mp4 /home/user/c09/video$index.mp4
cp /home/user/c09/transmission-log.txt /home/user/challengeServer/hosted_files/

#prep and copy pcap
date=`date +%s`
dateoffset=$(($date-1685453216))
editcap -t $dateoffset /home/user/c09/exemplar.pcapng /home/user/challengeServer/hosted_files/exemplar.pcapng


#copy token1 and video to web server
echo $t1 > /home/user/c09/token1

sleep 60

while [ $? -eq 1 ]
do
    echo "sleeping"
    sleep 5
    nc -zv 10.4.4.100 22 > /dev/null
done

sudo -u user ssh user@10.4.4.100 "echo 'M0r3S3cur34L\!f3' | sudo -S systemctl stop apache2"
sudo -u user ssh user@10.4.4.100 "echo 'M0r3S3cur34L\!f3' | sudo -S sed -i \"s/d>video$numb/d>$newname/g\" /var/www/html/ipv6/target/index.html"
sudo -u user ssh user@10.4.4.100 "echo 'M0r3S3cur34L\!f3' | sudo -S sed -i \"s/d>video$numb/d>$newname/g\" /var/www/html/ipv4/target/storage.html"
sudo -u user ssh user@10.4.4.100 "echo 'M0r3S3cur34L\!f3' | sudo -S mv /var/www/html/ipv4/target/ /var/www/html/ipv4/$webdir/"
sudo -u user ssh user@10.4.4.100 "echo 'M0r3S3cur34L\!f3' | sudo -S mv /var/www/html/ipv6/target/ /var/www/html/ipv6/$webdir/"
sudo -u user ssh user@10.4.4.100 "echo 'M0r3S3cur34L\!f3' | sudo -S sed -i "s/###/$dev/g" /var/www/html/ipv4/$webdir/index.html"
sudo -u user ssh user@10.4.4.100 "echo 'M0r3S3cur34L\!f3' | sudo -S sed -i "s/###/$dev/g" /var/www/html/ipv6/$webdir/index.html"
sudo -u user scp -i /home/user/.ssh/id_rsa -O /home/user/c09/token1 user@10.4.4.100:/var/www/html/ipv6/$webdir/
sudo -u user scp -i /home/user/.ssh/id_rsa -O /home/user/c09/video-names.txt user@10.4.4.100:/home/user/
sudo -u user scp -i /home/user/.ssh/id_rsa -O /home/user/c09/change-names.sh user@10.4.4.100:/home/user/
sudo -u user ssh user@10.4.4.100 "echo 'M0r3S3cur34L\!f3' | sudo -S chmod 755 /home/user/change-names.sh"
sudo -u user ssh user@10.4.4.100 "echo 'M0r3S3cur34L\!f3' | sudo -S /home/user/change-names.sh"
sudo -u user ssh user@10.4.4.100 "echo 'M0r3S3cur34L\!f3' | sudo -S rm -rf /home/user/change-names.sh /home/user/video-names.txt"
sudo -u user ssh user@10.4.4.100 "echo 'M0r3S3cur34L\!f3' | sudo -S systemctl start apache2"
sudo -u user ssh user@10.4.4.100 "echo 'M0r3S3cur34L\!f3' | sudo -S systemctl reload apache2"
sudo -u user ssh user@10.4.4.100 "echo 'M0r3S3cur34L\!f3' | sudo -S truncate -s 0 /var/log/auth.log"


#Add token file for grading check to Kali
while [ $? -eq 1 ]
do
    echo "sleeping"
    sleep 5
    nc -zv kali 22 > /dev/null
done

sudo -u user ssh user@kali "echo 'tartans' | sudo -S ping6 -c 4 ff02::2"
sudo -u user ssh user@kali "echo 'tartans' | sudo -S touch /home/user/Desktop/token.txt"
sudo -u user ssh user@kali "echo 'tartans' | sudo -S chown user /home/user/Desktop/token.txt"
