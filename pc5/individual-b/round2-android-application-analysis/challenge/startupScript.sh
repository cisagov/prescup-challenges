#!/bin/bash

# Copyright 2024 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.


client_key=$(vmtoolsd --cmd "info-get guestinfo.client_key")
echo $client_key > /home/user/ClientKey.txt
log_data=$(vmtoolsd --cmd "info-get guestinfo.log_data")
variant=$(vmtoolsd --cmd "info-get guestinfo.variant")
exif_data=$(vmtoolsd --cmd "info-get guestinfo.exif_data")

scp -r -i /home/user/.ssh/id_rsa -o 'StrictHostKeyChecking=no' /home/user/ClientKey.txt user@10.7.7.201:/home/user
echo "Done with scp command. Return value was $?"
sudo -u user ssh -t -t user@10.7.7.201 "sudo -S mv /home/user/ClientKey.txt /var/www/html/api/"
echo "Done with ssh client key command. Return value was $?"

exiftool -artist=${exif_data:0:1} -overwrite_original /home/user/imgs/2.png
exiftool -artist=${exif_data:1:1} -overwrite_original /home/user/imgs/4.png
exiftool -artist=${exif_data:2:1} -overwrite_original /home/user/imgs/6.png
exiftool -artist=${exif_data:3:1} -overwrite_original /home/user/imgs/8.png
exiftool -artist=${exif_data:4:1} -overwrite_original /home/user/imgs/10.png
exiftool -artist=${exif_data:5:1} -overwrite_original /home/user/imgs/12.png
exiftool -artist=${exif_data:6:1} -overwrite_original /home/user/imgs/14.png
exiftool -artist=${exif_data:7:1} -overwrite_original /home/user/imgs/16.png

scp -r -i /home/user/.ssh/id_rsa -o 'StrictHostKeyChecking=no' /home/user/imgs/*.png user@10.5.5.200:/home/user
echo "Done with scp images command. Return value was $?"
sudo -u user ssh -t -t user@10.5.5.200 "sudo -S mv /home/user/*.png /root/.cache/Google/AndroidStudio2022.2/device-explorer/Pixel_3a_API_34_extension_level_7_x86_64/data/data/com.companyname.androidprotektor/files/"  
echo "Done with ssh images command. Return value was $?"

if [ $variant -eq 0 ]
then
  scp -r -i /home/user/.ssh/id_rsa -o 'StrictHostKeyChecking=no' /home/user/1/com.companyname.androidprotektor.apk user@10.5.5.200:/home/user/Documents
  echo "Done with scp apk command. Return value was $?"
  
  # process db file
  #scp -r -i /home/user/.ssh/id_rsa -o 'StrictHostKeyChecking=no' /home/user/1/SQLite.db3 user@10.5.5.200:/home/user
  #echo "Done with scp db command. Return value was $?"
  #sudo -u user ssh -t -t user@10.5.5.200 "sudo -S mv /home/user/SQLite.db3 /root/.cache/Google/AndroidStudio2022.2/device-explorer/Pixel_3a_API_34_extension_level_7_x86_64/data/data/com.companyname.androidprotektor/files/"  
  #echo "Done with ssh db command. Return value was $?"
elif [ $variant -eq 1 ]
then
  scp -r -i /home/user/.ssh/id_rsa -o 'StrictHostKeyChecking=no' /home/user/2/com.companyname.androidprotektor.apk user@10.5.5.200:/home/user/Documents
  echo "Done with scp apk command. Return value was $?"
  
  # process db file
  #scp -r -i /home/user/.ssh/id_rsa -o 'StrictHostKeyChecking=no' /home/user/2/SQLite.db3 user@10.5.5.200:/home/user
  #echo "Done with scp log command. Return value was $?"
  #sudo -u user ssh -t -t user@10.5.5.200 "sudo -S mv /home/user/SQLite.db3 /root/.cache/Google/AndroidStudio2022.2/device-explorer/Pixel_3a_API_34_extension_level_7_x86_64/data/data/com.companyname.androidprotektor/files/"
  #echo "Done with ssh db command. Return value was $?"
elif [ $variant -eq 2 ]
then
  scp -r -i /home/user/.ssh/id_rsa -o 'StrictHostKeyChecking=no' /home/user/3/com.companyname.androidprotektor.apk user@10.5.5.200:/home/user/Documents
  echo "Done with scp apk command. Return value was $?"
  
  # process db file
  #scp -r -i /home/user/.ssh/id_rsa -o 'StrictHostKeyChecking=no' /home/user/3/SQLite.db3 user@10.5.5.200:/home/user
  #echo "Done with scp log command. Return value was $?"
  #sudo -u user ssh -t -t user@10.5.5.200 "sudo -S mv /home/user/SQLite.db3 /root/.cache/Google/AndroidStudio2022.2/device-explorer/Pixel_3a_API_34_extension_level_7_x86_64/data/data/com.companyname.androidprotektor/files/"
  #echo "Done with ssh db command. Return value was $?"    
elif [ $variant -eq 3 ]
then
  scp -r -i /home/user/.ssh/id_rsa -o 'StrictHostKeyChecking=no' /home/user/4/com.companyname.androidprotektor.apk user@10.5.5.200:/home/user/Documents
  echo "Done with scp apk command. Return value was $?"
  
  # process db file
  #scp -r -i /home/user/.ssh/id_rsa -o 'StrictHostKeyChecking=no' /home/user/4/SQLite.db3 user@10.5.5.200:/home/user
  #echo "Done with scp log command. Return value was $?"
  #sudo -u user ssh -t -t user@10.5.5.200 "sudo -S mv /home/user/SQLite.db3 /root/.cache/Google/AndroidStudio2022.2/device-explorer/Pixel_3a_API_34_extension_level_7_x86_64/data/data/com.companyname.androidprotektor/files/"
  #echo "Done with ssh db command. Return value was $?"          
fi

# log that the startup script is done and was successful
echo "Done startup configuration. All was successful."
