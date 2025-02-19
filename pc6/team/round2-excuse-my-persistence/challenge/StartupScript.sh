#!/bin/bash

#function to check return code for logging 
##############################################################
check_return_code() {
    if [ $? -eq 0 ]; then
        echo "$1 succeeded."
    else
        "echo $1 failed."
    fi
}
###############################################################

# pulls value of tokens out of guestinfo and puts it into a variable and writes token3 to a file
###############################################################

token1=$(vmtoolsd --cmd "info-get guestinfo.token1")
token2=$(vmtoolsd --cmd "info-get guestinfo.token2")
token3=$(vmtoolsd --cmd "info-get guestinfo.token3")

###############################################################

# Replace the text in the 3 php files with the token value
###############################################################

sed -i 's/########/'"$token3"'/g' /home/user/Documents/index.html
check_return_code "Updating index.html with token3"

echo $token1 > /home/user/Documents/token1.txt
check_return_code "Creating token1.txt"

echo $token2 > /home/user/Documents/token2.txt
check_return_code "Creating token2.txt"

################################################################

# scp the token files over to a different VM on the network. Echo the result as a log
################################################################
sshpass -p 'config_butnotforyou' scp -o "StrictHostKeyChecking=no" /home/user/Documents/token1.txt adonis_it_brian@10.5.5.119:/home/adonis_it_brian/token/token1.txt
check_return_code "scp token1.txt"

sshpass -p 'tartanspc6tartans' scp -o "StrictHostKeyChecking=no" /home/user/Documents/token2.txt root@10.4.4.53:/home/test/token2.txt
check_return_code "scp token2.txt"

sshpass -p 'tartanspc6tartans' ssh root@10.4.4.53 "chown test:test /home/test/token2.txt && chmod 600 /home/test/token2.txt"
check_return_code "chown token2.txt"

sshpass -p 'tartanspc6tartans' scp -o "StrictHostKeyChecking=no" /home/user/Documents/index.html user@10.4.4.71:/var/www/pc6/index.html
check_return_code "scp index.html"

################################################################


# log that the startup script is done and was successful
echo "Done startup configuration. All was successful."
