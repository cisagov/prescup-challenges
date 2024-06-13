
# Copyright 2024 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

#!/bin/bash

c1=`vmtoolsd --cmd "info-get guestinfo.c1"` # one of these at random; experience goalkeeper laboratory articulate leadership instrument disappoint television atmosphere artificial
c2=`vmtoolsd --cmd "info-get guestinfo.c2"` # one of these at random; researcher continuous microphone separation gregarious assignment experiment competence compromise investment
c3=`vmtoolsd --cmd "info-get guestinfo.c3"` # one of these at random; connection hypothesis pedestrian diplomatic commission helicopter reluctance vegetarian motorcycle understand

iteration=$(sudo -u user ssh -o StrictHostKeyChecking=no user@10.20.20.225 "cat /home/user/iterations.txt")
codes=$(sudo -u user ssh -o StrictHostKeyChecking=no user@10.20.20.225 "cat /home/user/codes.txt")
values=$(sudo -u user ssh -o StrictHostKeyChecking=no user@10.20.20.225 "cat /home/user/values.txt")

result=""

iteration_value=$(echo "$iteration" | tr -d '\n')

if [ "$iteration_value" -eq 0 ]; then
    echo "tartans" | sudo -u user ssh -o StrictHostKeyChecking=no user@10.20.20.225 "sudo echo '1' > /home/user/iterations.txt"
    echo "tartans" | sudo -u user ssh -o StrictHostKeyChecking=no user@10.20.20.225 "sudo rm -rf /home/user/codes.txt"
    echo "tartans" | sudo -u user ssh -o StrictHostKeyChecking=no user@10.20.20.225 "sudo rm -rf /home/user/values.txt"
    echo "tartans" | sudo -u user ssh -o StrictHostKeyChecking=no user@10.10.10.100 'sudo service cron stop'
    echo "tartans" | sudo -u user ssh -o StrictHostKeyChecking=no user@10.20.20.225 'sudo service cron stop'
    echo "tartans" | sudo -u user ssh -o StrictHostKeyChecking=no user@10.10.10.100 'sudo sed -i "s/alphabet/'"$c1"'/g" /var/spool/cron/crontabs/user'
    echo "tartans" | sudo -u user ssh -o StrictHostKeyChecking=no user@10.20.20.225 'sudo sed -i "s/parser0/parser1/g" /var/spool/cron/crontabs/user'
    echo "tartans" | sudo -u user ssh -o StrictHostKeyChecking=no user@10.10.10.100 'sudo service cron start'
    echo "tartans" | sudo -u user ssh -o StrictHostKeyChecking=no user@10.20.20.225 'sudo service cron start'
elif [ "$iteration_value" -eq 1 ]; then
    echo "$values" > /home/user/challengeServer/hosted_files/receivedvalues.txt
    if echo "$codes" | grep "$c1"; then
        result="$result GradingCheck1: Success -- You have boosted the first signal\n"
        result="$result GradingCheck2: Fail -- Incomplete: the second phase of the challenge has been initiated\n"
        result="$result GradingCheck3: Fail -- Incomplete: the second code has not been properly received\n"
        echo "tartans" | sudo -u user ssh -o StrictHostKeyChecking=no user@10.20.20.225 "sudo echo '2' > /home/user/iterations.txt"
        echo "tartans" | sudo -u user ssh -o StrictHostKeyChecking=no user@10.20.20.225 "sudo rm -rf /home/user/codes.txt"
        echo "tartans" | sudo -u user ssh -o StrictHostKeyChecking=no user@10.20.20.225 "sudo rm -rf /home/user/values.txt"
        echo "tartans" | sudo -u user ssh -o StrictHostKeyChecking=no user@10.20.20.225 'sudo service cron stop'
        echo "tartans" | sudo -u user ssh -o StrictHostKeyChecking=no user@10.20.20.225 'sudo sed -i "s/parser1/parser2/g" /var/spool/cron/crontabs/user'
        echo "tartans" | sudo -u user ssh -o StrictHostKeyChecking=no user@10.20.20.225 'sudo service cron start'
        # more to follow here to advance to phase 2
        echo "tartans" | sudo -u user ssh -o StrictHostKeyChecking=no user@10.10.10.100 'sudo service cron stop'
        echo "tartans" | sudo -u user ssh -o StrictHostKeyChecking=no user@10.10.10.100 'sudo sed -i "s/'"$c1"'/'"$c2"'/g" /var/spool/cron/crontabs/user'
        echo "tartans" | sudo -u user ssh -o StrictHostKeyChecking=no user@10.10.10.100 'sudo service cron start'
    else
    	result="$result GradingCheck1: Fail -- The first code has not been properly received\n"
        result="$result GradingCheck2: Fail -- Incomplete: the second code has not been properly received\n"
        result="$result GradingCheck3: Fail -- Incomplete: the second code has not been properly received\n"
    fi
elif [ "$iteration_value" -eq 2 ]; then
    echo "$values" > /home/user/challengeServer/hosted_files/receivedvalues.txt
    if echo "$codes" | grep "$c2"; then
        result="$result GradingCheck1: Success -- You have boosted the first signal\n"
        result="$result GradingCheck2: Success -- You have boosted the second signal\n"
        result="$result GradingCheck3: Fail -- Incomplete: the third phase of the challenge has been initiated\n"
        echo "tartans" | sudo -u user ssh -o StrictHostKeyChecking=no user@10.20.20.225 "sudo echo '3' > /home/user/iterations.txt"
        echo "tartans" | sudo -u user ssh -o StrictHostKeyChecking=no user@10.20.20.225 "sudo rm -rf /home/user/codes.txt"
        echo "tartans" | sudo -u user ssh -o StrictHostKeyChecking=no user@10.20.20.225 "sudo rm -rf /home/user/values.txt"
        echo "tartans" | sudo -u user ssh -o StrictHostKeyChecking=no user@10.20.20.225 'sudo service cron stop'
        echo "tartans" | sudo -u user ssh -o StrictHostKeyChecking=no user@10.20.20.225 'sudo sed -i "s/parser2/parser3/g" /var/spool/cron/crontabs/user'
        echo "tartans" | sudo -u user ssh -o StrictHostKeyChecking=no user@10.20.20.225 'sudo service cron start'
        # more to follow here to advance to phase 3
        echo "tartans" | sudo -u user ssh -o StrictHostKeyChecking=no user@10.10.10.100 'sudo service cron stop'
        echo "tartans" | sudo -u user ssh -o StrictHostKeyChecking=no user@10.10.10.100 'sudo sed -i "s/'"$c2"'/'"$c3"'/g" /var/spool/cron/crontabs/user'
        echo "tartans" | sudo -u user ssh -o StrictHostKeyChecking=no user@10.10.10.100 'sudo service cron start'
    else
        result="$result GradingCheck1: Success -- You have boosted the first signal\n"
        result="$result GradingCheck2: Fail -- The second code has not been properly received\n"
        result="$result GradingCheck3: Fail -- Incomplete: the second code has not been properly received\n"
    fi
elif [ "$iteration_value" -eq 3 ]; then
    echo $values > /home/user/challengeServer/hosted_files/receivedvalues.txt
    if echo "$codes" | grep "$c3"; then
        result="$result GradingCheck1: Success -- You have boosted the first signal\n"
        result="$result GradingCheck2: Success -- You have boosted the second signal\n"
        result="$result GradingCheck3: Success -- You have boosted the third signal\n"
    else
        result="$result GradingCheck1: Success -- You have boosted the first signal\n"
        result="$result GradingCheck2: Success -- You have boosted the second signal\n"
        result="$result GradingCheck3: Fail -- The third code has not been properly received\n"
    fi
else
	result="$result GradingCheck1: Fail -- The first code has not been properly received\n"
        result="$result GradingCheck2: Fail -- The second code has not been properly received\n"
        result="$result GradingCheck3: Fail -- The third code has not been properly received\n"
fi

printf "$result"



