#!/bin/bash

# Copyright 2024 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.


# Loading in all tokens
domainToken=$(vmtoolsd --cmd "info-get guestinfo.domainToken") #  a random word chosen to create the domain name, e.g. vessel.com
userToken=$(vmtoolsd --cmd "info-get guestinfo.userToken") #  a random word chosen to create the domain name, e.g. vessel.com
passToken=$(vmtoolsd --cmd "info-get guestinfo.passToken") # one of these at random; 643e2c87b708f5b3 14639fc05e49d3ec 8e2b2442542f6822 3fa23b24bedbc68a 816a4a83c6ce7071 c3644cbd30630c85 6d97e3a777c6de00 265666224ce878a7 bd65d44812209fcb
userNumsToken=$(vmtoolsd --cmd "info-get guestinfo.userNumsToken") # an integer between 100 and 999
ipToken=$(vmtoolsd --cmd "info-get guestinfo.ipToken") # an integer between 51 and 149
token1=$(vmtoolsd --cmd "info-get guestinfo.token1") # a 16 character hex string, e.g. 123abc456def1a2b
token2=$(vmtoolsd --cmd "info-get guestinfo.token2") # a 16 character hex string, e.g. 123abc456def1a2b
token3=$(vmtoolsd --cmd "info-get guestinfo.token3") # a 16 character hex string, e.g. 123abc456def1a2b
passToken3=$(vmtoolsd --cmd "info-get guestinfo.passToken3") # a 16 character hex string, e.g. 123abc456def1a2b

# Creating new vars with the loaded tokens
domain="${domainToken}.com" # The full domain (the domain is a random word)
username="${userToken}${userNumsToken}" # Username is a random word and 3 random nums
ip="10.2.2.${ipToken}"



# ================
# Add the IPs
# ================
# Add the chosen IP and remove the old IP
ip address add $ip dev ens34
ip address del 10.2.2.75 dev ens34
# Add the junk IPs, looping throgh 50-150
for i in {50..150};
do
    if [[ "$i" -ne "$ipToken" ]]; then
        ip address add 10.2.2.$i dev ens35;
    fi
done
# Set it so the site is only running on this one IP
sed -e "s/INSERT_IP/$ip/" /home/user/web_files/ports.conf > /etc/apache2/ports.conf

# ================
# Add token 2 to a hidden pdf in an encoded and reversed docx
# ================
# Add token2 to the corrupted file
sed -i -e "s/INSERT_TOKEN/$token2/" /home/user/files_to_analyze/mysterious_object/mysterious_object.pdf
# Create a directory and unzip the docx artifacts into it
mkdir /home/user/unzipped
cd /home/user/unzipped
unzip /home/user/files_to_analyze/mysterious_object/mysterious_object_found_tmp.docx
# Add the hidden pdf to the docx
mv /home/user/files_to_analyze/mysterious_object/mysterious_object.pdf mysterious_object.pdf
# Rezip the docx with the hidden pdf
zip -r /home/user/files_to_analyze/mysterious_object/mysterious_object_found.docx *
# Encode the docx
base64 -w 0 /home/user/files_to_analyze/mysterious_object/mysterious_object_found.docx > /home/user/files_to_analyze/mysterious_object/mysterious_object_found_enc.docx
# Reverse the encoded docx
cat /home/user/files_to_analyze/mysterious_object/mysterious_object_found_enc.docx | rev > /home/user/files_to_analyze/mysterious_object/mysterious_object_found.docx
# Move the docx to the web files directory and give it proper permissions
mv /home/user/files_to_analyze/mysterious_object/mysterious_object_found.docx /home/user/web_files/mysterious_object_found.docx
chmod 777 /home/user/web_files/mysterious_object_found.docx
# Move back to /home/user
cd


# ================
# Figuring out Token 3
# ================
cd /home/user/files_to_analyze/delidian/
sed -i -e "s/INSERT_PASS/$passToken3/" delidians.txt
pandoc delidians.txt -o delidians_recovered.pdf
xxd --ps -c 12 delidians_recovered.pdf | sed 's/\(..\)/\1 /g' > hex.txt
cat hex.txt | tr '[A-Za-z]' '[N-ZA-Mn-za-m]' > delidians_recovered.txt
sed -i -e "s/INSERT_3/$token3/" delidian_machine.pdf
zip -e -P $passToken3 delidian_machine.zip delidian_machine.pdf

zip delidian.zip delidians_recovered.txt delidian_machine.zip
chmod 777 delidian.zip
mv delidian.zip /home/user/web_files/delidian.zip
chmod 777 /home/user/web_files/delidian.zip
cd


# ================
# Select the stellarisIndex pdf with the proper password
# ================
# Create and populate a list of the possible password vals
passList="643e2c87b708f5b3 14639fc05e49d3ec 8e2b2442542f6822 3fa23b24bedbc68a 816a4a83c6ce7071 c3644cbd30630c85 6d97e3a777c6de00 265666224ce878a7 bd65d44812209fcb"
passArr=($passList)
# Find the file that should be shown to the user
stellarisIndex=0
for i in "${passArr[@]}"; do
    if [[ "$i" == "$passToken" ]]; then
        break
    fi
    stellarisIndex=$((stellarisIndex + 1))
done
# Copying over the correct file based on the randomly selected password
cp /home/user/files_to_analyze/challenge_us_files/stellaris_spacecraft/stellaris_spacecraft$stellarisIndex.pdf /home/user/files_to_analyze/challenge_us_files/stellaris_spacecraft.pdf
chmod 777 /home/user/files_to_analyze/challenge_us_files/stellaris_spacecraft.pdf

# ================
# Add the username to the metadata of each file on challenge.us
# ================
# Loop through the pdfs and add the creator (username) to a Creator metadata field
cd /home/user/files_to_analyze/challenge_us_files
documents=()
for i in *
do
    if test -f "$i"
    then
        exiftool -Creator=$username $i #1> /dev/null
        mv $i upload_files/$i #1> /dev/null
        chmod 777 upload_files/$i #1> /dev/null
        documents+="${i} "
    fi
done


# ================
# Upload the zip of files to challenge.us
# ================
cd /home/user/files_to_analyze/challenge_us_files/upload_files
# Move the updated files and zip them up
zip recovered_files.zip astronaut_qualities.pdf captain_amelia_vega.pdf spacecraft_evacuation_procedures.pdf celestial_guardians.pdf stellaris_spacecraft.pdf escape_pod_2.pdf stellar_voyager_x_12.pdf escape_pod.pdf town_alien_encounter.pdf galactic_explorer_corps.pdf gelorian_description.pdf xelarian_encounter.pdf operation_lunar_frontier.pdf xelarians_and_veridians.pdf
# Move the zip of files to the dir that allows the user to download them on challenge.us. Also give it proper permissions
cp recovered_files.zip /home/user/challengeServer/hosted_files/recovered_files.zip
chmod 777 /home/user/challengeServer/hosted_files/recovered_files.zip
cd




# ================
# Everything up until the script sleeps is related to configuring the website
# ================
# Create proper domain directories using the random domain
mkdir -p /var/www/$domain/public_html
chmod -R 755 /var/www

# Add the proper credentials to verify_login.php
# Adding the username
sed -e "s/!!user!!/$username/" /home/user/web_files/verify_login1.php > /home/user/web_files/verify_login2.php
# Hashing the pass
passHash=$(echo -n "$passToken" | sha1sum)
passHash=${passHash::-3}
# Adding the hashed pass
sed -e "s/!!pass!!/$passHash/" /home/user/web_files/verify_login2.php > /home/user/web_files/verify_login.php
chmod 777 /home/user/web_files/verify_login.php

# Adding token 1 to the storage page, which can only be accessed with proper credentials
sed -e "s/INSERT_TOKEN_1/$token1/" /home/user/web_files/storage.php > /home/user/web_files/storage2.php
#chmod 777 /home/user/web_files/storage2.php

# Copy over necessary web files
mv /home/user/web_files/index.html /var/www/$domain/public_html/index.html
mv /home/user/web_files/storage2.php /var/www/$domain/public_html/storage.php
mv /home/user/web_files/delidian.zip /var/www/$domain/public_html/delidian.zip
mv /home/user/web_files/mysterious_object_found.docx /var/www/$domain/public_html/mysterious_object_found.docx
mv /home/user/web_files/verify_login.php /var/www/$domain/public_html/verify_login.php
# Give both php files proper permissions
chown www-data:www-data /var/www/$domain/public_html/verify_login.php
chown www-data:www-data /var/www/$domain/public_html/storage.php
chmod 777 /var/www/$domain/public_html/storage.php
chmod 777 /var/www/$domain/public_html/verify_login.php


# Creating new virtual host files
# Filling in the domain
sed -e "s/!!!/$domain/" /home/user/web_files/000-default.conf > /home/user/web_files/tmp.conf
sed -e "s/INSERT_IP/$ip/" /home/user/web_files/tmp.conf > /home/user/web_files/$domain.conf
chmod 777 /home/user/web_files/$domain.conf
mv /home/user/web_files/$domain.conf /etc/apache2/sites-available/$domain.conf

# Replace the hosts file with a file containing the new ens34 ip
echo "$ip   $domain" >> /etc/hosts
echo "$ip   $domain" >> /etc/hosts.dnsmasq
echo "nameserver    $ip" >> /etc/resolv.conf

# SUDO VIM /etc/resolv.conf ADD namespace   example.com

# Enabling new virtual host files
cd /etc/apache2/sites-available 1> /dev/null
sudo a2ensite $domain.conf 1> /dev/null
sudo a2dissite 000-default.conf 1> /dev/null
sudo apache2ctl configtest 1> /dev/null
sudo systemctl restart apache2 1> /dev/null
# restart dnsmasq too just in case
systemctl reload dnsmasq 1> /dev/null
# Wait for the update to go through
sleep 5
