# Inception

*Challenge Artifacts*

This README file contains details on how the challenge was created. 

### mongo

Contains the files for the MongoDB container.

- [001-users.js](./mongo/001-users.js): An init script for MongoDB that runs when container is started.
  - Loads the user information.
- [002-support.js](./mongo/002-support.js): An init script for MongoDB that runs when container is started.
  - Loads the support information.
- [Dockerfile](./mongo/Dockerfile): The Docker file for the MongoDB container.

### pccc

Contains a Flask application for simulating the frontend of the President's Cup site.

- [app](./pccc/): Contains the files used by the Flask application.
  - [forms](./pccc/app/forms/): Contains the `Flask-WTF` code used to create the various HTML forms found throughout the site.
  - [static](./pccc/app/static/): Contains various files intended to be downloaded directly (that is, without first processing or logging in): site images, CSS, and JS.
    - [static/themes](./pccc/app/static/themes/): The save location for the images and markdown files which are updated via the `Admin` tab.
  - [templates](./pccc/app/templates/): Contains the HTML templates used by Flask
  - [app.py](./pccc/app/app.py): The Flask app containing the various routes for the site
  - [db.py](./pccc/app/db.py): Initializes the database connection for the site.
  - [game.yml](./pccc/app/game.yml): The initial configuration for the challenges.
  - [handle_yaml.py](./pccc/app/handle_yaml.py): The vulnerable script run as unprivileged user `yaml` that handles loading the uploaded YAML config.
  - [names.txt](./pccc/app/names.txt): A brief, static list of the auto-generated names taken from the PCCC website
  - [randomname.py](./pccc/app/randomname.py): A thread-safe script that retrieves and removes a name from `names.txt` during account registration.
- [Dockerfile](./pccc/Dockerfile): The Docker file for the Flask application.
- [entrypoint.sh](./pccc/entrypoint.sh): Real simple entrypoint script that loads one of the tokens before starting Flask.

### pccc

A simple Python Selenium bot that simulates a support user logging in and responding to support tickets.

- [Dockerfile](./selenium/Dockerfile): The Docker file for the Selenium bot.
- [entrypoint.sh](./selenium/entrypoint.sh): Initializes the support/admin users in the database, and then runs the bot script every few seconds.
- [init.py](./selenium/init.py): The init script that loads the users in the database.
- [support.py](./selenium/support.py): The Selenium bot that responds to support tickets.

## Challenge Environment Initial Setup Requirements 

This challenge is run entirely using Docker and Docker compose, so start up is very straightforward.

### Installing Docker

First, install Docker and Docker compose, using the official docker instructions for whichever operating system you are using. The entire challenge can then be launched easily using 

`docker compose up -d`

TODO: Add any details about getting in? Maybe VNC?

### Grading

This challenge does not involve grading.
