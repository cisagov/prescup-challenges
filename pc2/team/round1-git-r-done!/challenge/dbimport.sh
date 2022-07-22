#!/bin/bash

# Copyright 2022 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

mysql -e "CREATE DATABASE clientdev"
mysql -e "CREATE USER 'clientdev'@'localhost' IDENTIFIED BY '54b4aaf1' "
mysql -e "GRANT ALL PRIVILEGES ON clientdev.* TO 'clientdev'@'localhost';"
mysql -e "FLUSH PRIVILEGES"
