#!/bin/bash

# Copyright 2022 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

##### Update apps and install mysql and pip ##########
apt update -y
apt install mysql-server -y
apt install pip -y
######################################################

########### Install pip dependencies #################
pip install -r ./requirements.txt 
######################################################

########### Create mySQL DB, User, and permissions ###
mysql -e "CREATE DATABASE awfulbb"
mysql -e "CREATE USER 'awfulbb'@'localhost'"
mysql -e "GRANT ALL PRIVILEGES ON awfulbb.* TO 'awfulbb'@'localhost';"
######################################################

########### Import db ################################
gunzip < ./awfulbb/awfulbb.sql.gz | mysql awfulbb
######################################################

########## Download and unzip gecko driver ######################
wget -qO - https://github.com/mozilla/geckodriver/releases/download/v0.30.0/geckodriver-v0.30.0-linux64.tar.gz | tar -xvzf - -C ./
#################################################################

############### Run exploit site ################################
nohup python3 ../attacker-site.py &
#################################################################
