# Finsta

*Challenge Artifacts*

This README file contains details on how the challenge was created and how it could be recreated in a different environment. 

### finsta:

The [finsta](./finsta/) folder contains the Finsta Flask application. The following describes the directory structure and any files of special interest.

- [app.py](./finsta/app.py): The main Flask application. Defines the routes and their logic.
- [forms](./finsta/forms/): The `forms` directory contains the various forms used by the Finsta application. They are defined for use with Flask Bootstrap. For example, [loginForm.py](./finsta/forms/loginForm.py) defines the fields for the login form.
- [instance/socialmedia.db](./finsta/instance/socialmedia.db): A SQLite database containing the initial state of the Finsta users. Note the flag is not present; it is inserted when the application is launched.
- [models/User.py](./finsta/models/User.py): Defines the User and Post models to retrieve from the database using Flask sqlalchemy. Also defines User as the class to use during login with Flask Login.
- [static](./finsta/static/): Contains all of the static files to download (JS, CSS, and images).
- [templates](./finsta/templates/): The Jinja html templates used to design the website layout. The [base.html](./finsta/templates/base.html) file defines the overall structure, while each of the other files (except [index.html](./finsta/templates/index.html)) define the main to load into `base.html`. 

### scripts:

- [runXSS.py](./scripts/runXSS.py): Used by `challenge.us` to look up posts that would be interesting to Greg and then, if found, simulate a user navigating to `finsta.us` by executing [xss/doXSS.js](./scripts/xss/doXSS.js).
- [xss/doXSS.js](./scripts/xss/doXSS.js): Uses the [jsdom](https://github.com/jsdom/jsdom) library to simulate a browser DOM and execute the user-injected Javascript. The token is loaded into a cookie here.
- [xss/packages.json](./scripts/xss/packages.json): The list of packages needed for [xss/doXSS.js](./scripts/xss/doXSS.js). Only `jsdom` is listed; dependencies will be installed automatically.

## Challenge Environment Initial Setup Requirements 

### Setting up the Finsta Flask App

The first step is to install all of the requirements for the Flask application and to install gunicorn and nginx for hosting.

```bash
pip install flask flask-jwt-extended Flask-SQLAlchemy Flask-Bootstrap Flask-Login Flask-WTF
sudo apt install nginx gunicorn
```

Now we set up the service to run the server and use nginx to expose it on port 80.

```none
[Unit]
Description=Gunicorn instance to serve Finsta app
After=network.target

[Service]
User=user
Group=www-data
WorkingDirectory=/home/user/app
ExecStart=/bin/gunicorn --workers 3 --bind unix:flask.sock -m 007 app:app

[Install]
WantedBy=multi-user.target
```

```none
server {
    listen 80;
    server_name finsta.us;

    location / {
        include proxy_params;
        proxy_pass http://unix:/home/user/app/flask.sock;
    }
}
```

### Triggering XSS

The XSS script uses paramiko to connect to the finsta VM.

```bash
pip install paramiko
```

The grading script wants to log to `/var/log/challengeGrader/gradingCheck.log`. Create the folder and assign the correct permissions, or change the log file to somewhere writeable.

```bash
sudo mkdir /var/log/challengeGrader
sudo chown user /var/log/challengeGrader
sudo chgrp user /var/log/challengeGrader
```

Finally, install nodejs and the necessary packages for doXSS.js.

```bash
sudo apt install npm
sudo npm install -g n
sudo n stable  # Make sure we have the latest version so jsdom works correctly
cd xss
npm install
```

Run the runXSS.py script when user interaction is needed from Greg for the XSS task. The script works by

1. Downloading the socialmedia.db to analyze the current posts, and
2. executing the doXSS.js script, which uses jsdom to actually perform simulate the XSS attack, for every user profile identified as "interesting" to Greg.

## Cover Tracks

Prior to saving the server templates, clear the history to prevent competitors from reviewing any previously run commands. 
 
```bash
history -c && history -w
```
