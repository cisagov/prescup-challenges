#!/bin/bash

# Copyright 2024 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

dev=`vmtoolsd --cmd "info-get guestinfo.devnum"` # an integer between 250 and 480
serial=`echo VIGEY5000-4203-91-$dev`
serialbase=$(echo -n $serial | base64)
webdir="${serialbase%%=*}"
token3=`vmtoolsd --cmd "info-get guestinfo.t3"` # a 12 character hex string, e.g. 12ab34cd56ef

result=""
file_path="/home/user/challengeServer/hosted_files/remediation.txt"

# check if the file already exists in hosted files, implying they have already passed the token check

if [ -f "$file_path" ]; then
    count=0
    
    sites="$webdir VklHRVk1MDAwLTc4OTItNDctNTAz VklHRVk1MDAwLTcwOTQtNjktNTI0 VklHRVk1MDAwLTE4NTYtMzgtNDk3 VklHRVk1MDAwLTgzNzEtMjMtODY1 VklHRVk1MDAwLTI1NjctMTUtMTAz VklHRVk1MDAwLTkzODQtMTAtMjQ2 VklHRVk1MDAwLTMyNjUtODItOTY1 VklHRVk1MDAwLTY3MzltNzQtNjgy VklHRVk1MDAwLTU0MTctNTktODEy"
    
    for site in $sites 
    do
        wget -6 -O "/home/user/c09/$site.html" "http://[fdab:1:1:2::1002]/$site"
        wget -6 -O "/home/user/c09/verify-$site.php" "http://[fdab:1:1:2::1002]/$site/verify_login.php"
        if grep -q "Login" /home/user/c09/$site.html && grep -q "success" "/home/user/c09/verify-$site.php" "http://[fdab:1:1:2::1002/$site/verify_login.php"; then
            count=$((count+1))
        fi
    done


    if [ $count -eq 10 ]; then
        result="GradingCheck2: Success - You have successfully implemented the required remediation for all 10 IPv6 camera sites."
    else
        result="GradingCheck2: Failure - The required remediation was not implemented for all 10 sites, or the sites could not be contacted. Please ensure the sites are accessible and have the proper remediation applied. Currently you have remediated $count out of 10 sites"
    fi

else
    # grab the remote file via ssh
    remote_content=$(sudo -u user ssh user@kali "cat /home/user/Desktop/token.txt")
        
    # Compare the remote file with the token
    if [ "$remote_content" = "$token1" ]; then
        # copy the remediation file
        cp /home/user/c09/remediation.txt $file_path
        result="GradingCheck1: Success - Token value matches. Further instructions have been placed at https://challenge.us/files. Subsequent executions of this check will only validate that the remediation task has been implemented properly."
    else
        result="GradingCheck1: Failure - The contents of your token.txt file do not match the token string you should have found. Please check the string for accuracy and ensure you have properly located the first token."
    fi
fi

printf "$result"


