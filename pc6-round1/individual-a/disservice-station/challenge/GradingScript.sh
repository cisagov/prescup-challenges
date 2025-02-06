#!/bin/bash
#
# Copyright 2025 Carnegie Mellon University.
#
# NO WARRANTY. THIS CARNEGIE MELLON UNIVERSITY AND SOFTWARE ENGINEERING INSTITUTE MATERIAL IS FURNISHED ON AN "AS-IS" BASIS. CARNEGIE MELLON UNIVERSITY MAKES NO WARRANTIES OF ANY KIND, EITHER EXPRESSED OR IMPLIED, AS TO ANY MATTER INCLUDING, BUT NOT LIMITED TO, WARRANTY OF FITNESS FOR PURPOSE OR MERCHANTABILITY, EXCLUSIVITY, OR RESULTS OBTAINED FROM USE OF THE MATERIAL. CARNEGIE MELLON UNIVERSITY DOES NOT MAKE ANY WARRANTY OF ANY KIND WITH RESPECT TO FREEDOM FROM PATENT, TRADEMARK, OR COPYRIGHT INFRINGEMENT.
#
# Licensed under a MIT (SEI)-style license, please see license.txt or contact permission@sei.cmu.edu for full terms.
#
# [DISTRIBUTION STATEMENT A] This material has been approved for public release and unlimited distribution.  Please see Copyright notice for non-US Government use and distribution.
#
# This Software includes and/or makes use of Third-Party Software each subject to its own license.
# DM25-0166#


result=""

#### Token 1 ####
login_url="http://10.5.5.100/login.php"

## test login ##
logintest=$(curl -s -X POST -d "username=testuser&password=test" $login_url)

## perform sql injection ##
response1=$(curl -s -X POST -d "username=' OR 1=1--&password=123" $login_url)

if [[ "$logintest" == *"Login successful!"* ]];
then
    if [[ "$response1" != *"Login successful!"* ]];
    then
        result="$result \n GradingCheck1: Success -- SQL Injection Fixed!\n"
    else
        result="$result \nGradingCheck1: Fail -- SQL injection not fixed.\n"
    fi
else
    result="$result GradingCheck1: Fail -- Could not log in.\n"
fi

#### Token 2 ####
upload_url="http://10.5.5.100/upload.php"
username="testuser"
password="test"

## remove testfile from any prior attempts ##
ssh -o StrictHostKeyChecking=no root@10.5.5.100 "rm -f /var/www/html/uploads/testfile.php"

## get session cookie ##
curl -s -c cookies.txt -X POST -d "username=$username&password=$password" "$login_url"

## Upload the file ##
uploadtest=$(curl -s -b cookies.txt -F "file=@/home/user/challengeServer/uploadtest.pdf" "$upload_url" | grep "uploadtest.pdf")
response2=$(curl -s -b cookies.txt -F "file=@/home/user/challengeServer/testfile.php" "$upload_url")

## Attempt to trigger the uploaded php file ##
if [[ "$uploadtest" == *"uploadtest.pdf has been uploaded."* ]];
then
    if curl -s http://10.5.5.100/uploads/testfile.php | grep "This is a malicious file.";
    then
        result="$result GradingCheck2: Fail -- File Injection Not Fixed.\n"
    else
        result="$result GradingCheck2: Success -- File Injection Vulnerability Fixed!\n"
    fi
else
    result="$result GradingCheck2: Fail -- Can not upload files\n"
fi

## Kill the session ##
curl -s -b cookies.txt "$logout_url"
rm -f cookies.txt

#### Token 3 ###
## URL of the registration page ##
url="http://10.5.5.100/register.php"

## Generate a random username so "User Exists" error will not break the script ##
username="user_$(date +%s%N)"

## Set up passwords for checking ##
weak_tooshort="Abc1"
weak_noupper="abcdefg1"
weak_nolower="ABCDEFG1"
weak_nonumber=ABCDefgh
strong_password="Str0ngPassw0rd1"

## Use curl to send POST requests with weak password and unique username  ##
## too short ##
responseshort=$(curl -s -X POST -d "username=$username&password=$weak_tooshort&confirm_password=$weak_tooshort" "$url")
## Reset User ##
username="user_$(date +%s%N)"
## No Upper ##
responsenoupper=$(curl -s -X POST -d "username=$username&password=$weak_noupper&confirm_password=$weak_noupper" "$url")
## Reset User ##
username="user_$(date +%s%N)"
## No Lower ##
responsenolower=$(curl -s -X POST -d "username=$username&password=$weak_nolower&confirm_password=$weak_nolower" "$url")
## Reset User ##
username="user_$(date +%s%N)"
## No Number ##
esponseshort=$(curl -s -X POST -d "username=$username&password=$weak_nonumber&confirm_password=$weak_nonumber" "$url")
## Reset User ##
username="user_$(date +%s%N)"
## Try Strong Password ##
responsestrong==$(curl -s -X POST -d "username=$username&password=$strong_password&confirm_password=$strong_password" "$url")

# Check if the response allows registration with weak password

if [[ "$responseshort" == *"Registration successful"* || \
        "$responsenoupper" == *"Registration successful"* || \
        "$responsenolower" == *"Registration successful"* || \
    "$responsestrong" != *"Registration successful"* ]]; then
    result="$result GradingCheck3: Fail -- Password Policy Not Fixed.\n"
else
    result="$result GradingCheck: Success -- Password Policy Fixed!"
fi

printf "$result"