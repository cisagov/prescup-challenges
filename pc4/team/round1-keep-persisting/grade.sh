#!/bin/bash

# Copyright 2023 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

###########################
#### SSH PERSISTENCE #####
###########################

echo "Persistence_Check_1 : Success -- ssh persistence implementation is not possible outside hosted environment. Points granted."
SSH_PERSISTENCE=1

###########################
#### CRON PERSISTENCE #####
###########################

## Files related to cron persistence
CRON2=/tmp/cron_executable.sh
CRON3=/tmp/defacecron

## Directory to find related to cron persistence
CRON_DIR=/tmp/p2wj96

## Temporary cron file to view crontab content
crontab -l > /tmp/gradingcron
CRON_TMP=/tmp/gradingcron

## Text appended granting access and/or persitence to attacker
CRON_GREP1=$( grep -Fc "* * * * * rm -rf /var/www/html/*" $CRON_TMP )
CRON_GREP2=$( grep -Fc "* * * * * cp -r /tmp/p2wj96/* /var/www/html/" $CRON_TMP )

CRON_GREP3=$( grep -Fc "#* * * * * rm -rf /var/www/html/*" $CRON_TMP )
CRON_GREP4=$( grep -Fc "#* * * * * cp -r /tmp/p2wj96/* /var/www/html/" $CRON_TMP )

if [[ "$CRON_GREP3" -eq 1 || "$CRON_GREP4" -eq 1 ]] ;
    then
	CRON_GREP1=0
	CRON_GREP2=0
    else
    	:
fi

## This if statement makes sure EVERY file, directory or method of CRON persistence has been removed

if [[ "$CRON_GREP1" -eq 1 || "$CRON_GREP2" -eq 1 || -d "$CRON_DIR" || -f "$CRON2" || -f "$CRON3" ]] ;
    then
        echo "Persistence_Check_2 : Failure -- At least one trace of this persistence exists."
        CRON_PERSISTENCE=0
    else
        echo "Persistence_Check_2 : Success -- All cron persistence removed."
        CRON_PERSISTENCE=1
fi

rm $CRON_TMP


##############################
#### SYSTEMD PERSISTENCE #####
##############################

## Files to find related to systemd persistence
SYSTEMD1=/home/$USER/.config/systemd/user/WICKED.service
SYSTEMD2=/home/$USER/.config/systemd/user/WICKED.timer
SYSTEMD3=/home/$USER/.config/systemd_script.sh
SYSTEMD4=/home/$USER/.config/systemd_vicious.sh
SYSTEMD5=/home/$USER/.config/systemd/user/default.target.wants/WICKED.service
SYSTEMD6=/home/$USER/.config/systemd/user/timers.target.wants/WICKED.timer

## Directory to find related to systemd persistence
SYSTEMD_DIR=/home/$USER/.config/deface

## This if statement makes sure EVERY file, directory or method of SYSTEMD persistence has been removed

if [[ -d "$SYSTEMD_DIR" || -f "$SYSTEMD1" || -f "$SYSTEMD2" || -f "$SYSTEMD3" || -f "$SYSTEMD4" || -f "$SYSTEMD5" || -f "$SYSTEMD6" ]] ;
    then
        echo "Persistence_Check_3 : Failure -- At least one trace of this persistence exists."
        SYSTEMD_PERSISTENCE=0
    else
        echo "Persistence_Check_3 : Success -- All systemd persistence removed."
        SYSTEMD_PERSISTENCE=1
fi

##############################
##### BASHRC PERSISTENCE #####
##############################

echo "Persistence_Check_4 : Success -- bashrc persistence implementation is not possible outside hosted environment. Points granted."
BASHRC_PERSISTENCE=1


##############################
#####  BACKUP COMPLETE   #####
##############################
BACKUP1=/var/www/html/index.html
BACKUP2=/var/www/html/bootstrap.min.css
BACKUP3=/var/www/html/style.css

if [[ "$SSH_PERSISTENCE" -eq 1 && "$CRON_PERSISTENCE" -eq 1 && "$SYSTEMD_PERSISTENCE" -eq 1 && "$BASHRC_PERSISTENCE" -eq 1 && -f "$BACKUP1" && -f "$BACKUP2" && -f "$BACKUP3" ]] ;
    then
        echo "Backup_Complete : Success -- All possible methods of persistence removed and backup implemented correctly. For the full experience, access the archive site"
    else
        echo "Backup_Complete : Failure -- At least one method of persistence exist or backup not implemented correctly. Make sure to add backup files under /var/www/html/"
fi
