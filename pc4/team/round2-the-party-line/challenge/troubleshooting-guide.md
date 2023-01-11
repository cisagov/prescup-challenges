# c26 - The Party Line - Troubleshooting Guide

Infinity challenge

User deployment should consist of the following machines:  
enterprise-server - users must find "user" password during challenge  
kali - should have wordlist.iso attached at startup  
dsmith - users only have "user" account creds  
awilliams - users only have "user" account creds  
rknight - users only have "user" account creds  

There are checks for each machine (see below) which loop for 5 seconds and sleep until they are avaialble. This prevents the startup script from trying to copy files before they have been deployed. If the startup script appears to be hanging, you might need to destroy and redeploy the challenge to ensure a clean deployment occurs.



## Tips for confirming a correct deployment

Support desk personnel can connect to the challenge server and ssh into the following machines to make sure all files have been deployed:  
angelawilliams@10.5.5.152:/home/angelawilliams/Documents/share.zip  
scrtftp@10.5.5.160:/home/scrtftp/2048Game.zip  
donnasmith@10.5.5.151:/home/donnasmith/Downloads/licensekey.jpg  

Checking the user account password on enterprise server  
Get the "user" account password from the challenge server - /home/user/challengeServer/custom_scripts/expectoutput.txt  
ssh to user@10.5.5.160 with the new creds to verify the password change was successful  



## The final check involves server remediation  
The grading script checks for server remediation efforts . . .   
checks if ftp server is running on 10.5.5.160:32210 - if FTP server is available, test fails  
checks if web server is available on 10.5.5.160:80 - if web server is not available, test fails  
checks if IRC is running on 10.5.5.160:6667 - if IRC is not available, test fails  



## Below is a copy of the challenge server startup script, which may be useful for troubleshooting during the competition

<pre><code>
# get tokens from topomojo
zippassword=$(vmtoolsd --cmd "info-get guestinfo.zippassword")
serverpassword=$(vmtoolsd --cmd "info-get guestinfo.serverpassword")
licensekey=$(vmtoolsd --cmd "info-get guestinfo.licensekey")

# make sure enterprise server is running
nc -zv 10.5.5.160 22 > /dev/null

while [ $? -eq 1 ]
do
sleep 5
nc -zv 10.5.5.160 22 > /dev/null
done

# make sure awilliams is running
nc -zv 10.5.5.152 22 > /dev/null

while [ $? -eq 1 ]
do
sleep 5
nc -zv 10.5.5.152 22 > /dev/null
done

# create password protected zip file
echo "FTP Server: 10.5.5.160:32210" > /home/user/passwords
echo "username: scrtftp" >> /home/user/passwords
echo "password: Km73pDXf" >> /home/user/passwords
echo "username: user" >> /home/user/passwords
echo "password: $serverpassword" >> /home/user/passwords
zip -r -j -P $zippassword /home/user/share.zip /home/user/passwords
scp -r -i /home/user/.ssh/id_rsa -o "StrictHostKeyChecking=no" /home/user/share.zip angelawilliams@10.5.5.152:/home/angelawilliams/Documents

# create encrypted random beacon value that the game POSTS
beacon=$(vmtoolsd --cmd "info-get guestinfo.beacon")
#echo -n $beacon | openssl enc -aes-128-cbc -base64 -nosalt -out /home/user/Downloads/2048/data.txt -K 1739b40d736d1488 -iv 768b43d6179b9f91
echo -n $beacon | openssl enc -aes-128-cbc -base64 -nosalt -out /home/user/Downloads/2048/data.txt -K 31373339623430643733366431343838 -iv 37363862343364363137396239663931

#echo -n $beacon > /home/user/beacon.txt
#openssl enc -aes-128-cbc -nosalt -in /home/user/beacon.txt -out /home/user/encrypted_beacon.txt -K 1739b40d736d1488 -iv 768b43d6179b9f91
#base64 -e /home/user/encrypted_beacon.txt /home/user/Downloads/2048/data.txt
zip -r -j /home/user/challengeServer/custom_scripts/2048Game.zip /home/user/Downloads/2048/
# move the app to the ftp server
scp -r -i /home/user/.ssh/id_rsa -o "StrictHostKeyChecking=no" /home/user/challengeServer/custom_scripts/2048Game.zip scrtftp@10.5.5.160:/home/scrtftp

# make sure dsmith is running
nc -zv 10.5.5.151 22 > /dev/null

while [ $? -eq 1 ]
do
sleep 5
nc -zv 10.5.5.151 22 > /dev/null
done

# create an image with license key text and move it to a user machine
convert -pointsize 25 -fill yellow -draw "text 300,50 'License Key: $licensekey'" /home/user/Pictures/Wallpapers/pc3n32.png /home/user/challengeServer/custom_scripts/licensekey.jpg
scp -r -i /home/user/.ssh/id_rsa -o "StrictHostKeyChecking=no" /home/user/challengeServer/custom_scripts/licensekey.jpg donnasmith@10.5.5.151:/home/donnasmith/Downloads

# set user account password on remote server via expect script
expect /home/user/challengeServer/custom_scripts/expectscript.sh user tartans user@10.5.5.160 $serverpassword > /home/user/challengeServer/custom_scripts/expectoutput.txt

# log that the startup script is done and was successful
echo "Done startup configuration. All was successful."
</code></pre>





