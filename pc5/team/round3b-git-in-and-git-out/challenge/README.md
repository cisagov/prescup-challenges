# Git In and Git Out

*Challenge Artifacts*

## IMPORTANT
This challenge is only partially open-sourced. The files in this directory are provided as a starting point if you wish to recreate the challenge on your own. The full version of the challenge can be played on the hosted site.

## [webserver](./webserver/)

The files included for the web server should be placed in the `/var/www/` folder on the web server and given to the competitor to ascertain how the web server works. 

## Additional Challenge Setup Description

The original challenge included a Redis and MySQL server. Redis caches the session information for login. MySQL contains a single user table with the following fields: `Username`, `Password`, and `isadmin`. The table has one non-admin user.