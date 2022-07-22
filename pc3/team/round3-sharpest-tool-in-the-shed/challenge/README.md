# Sharpest Tool in the Shed

## !! SPOILER ALERT !!
This document contains notes to configure the included assets for use as in a challenge environment. Reading this document will provide hints that could be useful for solving the challenge.
<br><br>
## Challenge Setup Notes

The description below assumes the environment will contain at least three separate machines including a web server, secret server and an attack machine that the the competitor will use to solve the challenge. 
<br><br>

**Web Server Setup**

Our example used a linux host with the Apache web server, but this is not a requirement.<br>
This server hosts the target web site http://admin-tools.us and is assumed to have an IP address of 10.5.5.10.
MongoDB was used in this challenge, but any database server could be used.<br>
The connection string can be found in /var/www/html/servery.py - "mongodb://localhost:27017/userDB"<br>
The userSetter.sh file is located at /home/user/tokens.<br>
You will need to replace $adminToken in /var/www/html/templates/site.html and $catToken in /var/www/html/token.txt with custom values for your scenario.<br>
When the /home/user/tokens/userSetter.sh shell script runs a random user is inserted into the user collection of the userDB. In the script we are using a guestinfo variable, but this can be changed for your environment.<br>
The /var/www/html contains the code that the attacker interacts with when using the web application.<br>
server.py interacts with the database to check user login attempts, redirect the user to the site after authentication and alert them of unauthorized access attempts. 
<br><br>

**Secret Server Setup**

Our example used a linux host with the Apache web server, but this is not a requirement.<br>
This server should be configured so it only responds to HTTP GET requests from the web server. You will notice that /var/www/html/index.php script specifically denies requests unless they come from 10.5.5.10.<br>
The index.php and ping.php files were located at /var/www/html<br>
The /var/www/html/index.php provides the ssrfToken that the attacker needs to find as part of the solution.<br>
You will need to replace the $ssrfToken variable in /var/www/html/index.php with a custom value for your scenario.<br>
ping.php is used by the /var/www/html/templates/site.html page of the web server to display the status of the secret server.
<br><br>

**Attack Machine**

Use your desired platform and tools, for example Kali Linux.
To browse to http://admin-tools.us on the web server you will need to provide DNS services or add a record to your attack machine's host settings.
<br><br>
## Suggested Technologies
Apache web server - https://httpd.apache.org/<br>
MongoDB database server - https://www.mongodb.com/<br>
Python drivers for MongoDB - https://docs.mongodb.com/drivers/python/<br>
Flask web application framework - https://palletsprojects.com/p/flask/