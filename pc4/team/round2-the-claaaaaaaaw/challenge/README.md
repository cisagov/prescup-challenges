# The Claaaaaaaaw!

_Challenge Artifacts_

- [aerial-images](./aerial-images) - a collection of images that are provided to competitors as intelligence
- [alien-reports.pdf](./alien-reports.pdf) and [alien-reports.pptx](./alien-reports.pptx) - intelligence reports that are provided to competitors
- [phone_logs.txt](./phone-logs.txt) - a log file of phone records that is provided to competitors as intelligence
- [index.php](./index.php) - the website for `The CLAW`
- [code.sql](./code.sql) - a SQL database export from `The CLAW`


_Setup_

Users were provided a Virtual Machine with all intelligence artifacts on the Desktop. This VM should be on the same network as `The CLAW` website.


## CLAW Installation

1. Create an Ubuntu 22.04 LTS Server
2. Place [code.sql](./code.sql) and [index.php](./index.php) in your home directory (for now)
3. Run the following bash commands to begin system configuration:
```bash
-sudo apt update
-sudo apt install mysql-server
-sudo systemctl start mysql-server
-sudo systemctl enable mysql-server
-sudo systemctl status mysql-server
-sudo cat /etc/mysql/debian.cnf
```
4. Take note of the user and password and create the CLAW database
```bash
sudo mysql -u <user> -e "create database pc"
```

5. Use the username found in the debian.cnf and enter the password, when asked, found in the `debian.cnf`
```bash
-sudo mysql -u <user> -p pc < code.sql
-sudo apt install apache2 php
-sudo rm /var/www/html/index.html
-sudo vim index.php
```
_Set username and password to the same as found in debian.cnf above_

6. Complete website configuration
```bash
sudo mv index.php /var/www/html/index.php
sudo systemctl start apache2
sudo systemctl enable apache2
sudo systemctl status apache2
```

7. Verify the user machine can now browse to port 80 of the Ubuntu Server
