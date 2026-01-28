#!/bin/bash

# Copyright 2025 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.


isadmin=$(vmtoolsd --cmd "info-get guestinfo.isadmin")
echo isadmin > isadmin.txt

pwdspraycount=$(vmtoolsd --cmd "info-get guestinfo.pwdspraycount")
echo pwdspraycount > pwdspraycount.txt

# move isadmin token to web server
# scp -i /home/user/.ssh/id-rsa -o 'StrictHostKeyChecking=no' ./isadmin.txt user@10.2.2.100:/home/var/www/html/
# echo "Done with scp command for isadmin token. Return value was $?"

# log that the startup script is done and was successful
# echo "Done with startup configuration. All was successful."

#function to check return code for logging 
#############################################################
check_return_code() {
    if [ $? -eq 0 ]; then
        echo "$1 succeeded."
    else
        "echo $1 failed."
    fi
}
###############################################################\
# pulls value of tokens out of guestinfo and puts it into a variable and writes token3 to a file
###############################################################

pwdspraycount=$(vmtoolsd --cmd "info-get guestinfo.pwdspraycount")
isadmin=$(vmtoolsd --cmd "info-get guestinfo.isadmin")
bcampbellcracked=$(vmtoolsd --cmd "info-get guestinfo.bcampbellcracked")

###############################################################
# Replace the text in the php files with the token value
###############################################################

sed -i 's/ia########/'"$isadmin"'/g' /home/user/Documents/login.php
check_return_code "Updating login.php with isadmin"

sed -i 's/bc########/'"$bcampbellcracked"'/g' /home/user/Documents/index.php
check_return_code "Updating index.php with bcampbellcracked"

sed -i 's/ia########/'"$isadmin"'/g' /home/user/Documents/index.php
check_return_code "Updating index.php with isadmin"


####################Not needed for this lab########################### 
# sed -i 's/########/'"$token2"'/g' /home/user/Documents/orders.php  #
# check_return_code "Updating orders.php with token2"                # / this is for adding a token to check user bcampbell's order page
#                                                                    #          
# echo $token3 > /home/user/Documents/token3.txt                     #
# check_return_code "Creating token3.txt"                            #
# sed -i 's/########/'"$token4"'/g' /home/user/Documents/checkout.php#  / this is for adding a token to check for checking out with hidden items.
# check_return_code "Updating checkout.php with token4"              #
######################################################################

#######################################################################################
# scp the token files over to a different VM on the network. Echo the result as a log #
#######################################################################################

scp -o "StrictHostKeyChecking=no" /home/user/Documents/login.php user@10.3.3.55:/var/www/html
check_return_code "scp login.php"

scp -o "StrictHostKeyChecking=no" /home/user/Documents/index.php user@10.3.3.55:/var/www/html
check_return_code "scp index.php"

#################### Not Needed Currently ####################################################
# scp -o "StrictHostKeyChecking=no" /home/user/Documents/orders.php 10.3.3.55:/var/www/html  #
# check_return_code "scp orders.php"                                                         #
# scp -o "StrictHostKeyChecking=no" /home/user/Documents/token3.txt 10.3.3.55:/var/www       #  / this part is for testing the directory traversal vulnerability
# check_return_code "scp orders.php"                                                         #
# scp -o "StrictHostKeyChecking=no" /home/user/Documents/checkout.php 10.3.3.55:/var/www/html#
# check_return_code "scp checkout.php"                                                       #
##############################################################################################

# log that the startup script is done and was successful
echo "Done with startup configuration. All was successful."
