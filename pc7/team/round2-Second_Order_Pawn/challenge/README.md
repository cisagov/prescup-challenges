# Second-Order Pawn

*Challenge Artifacts*

This README file contains details on how the challenge was created. 

### pawndata

Contains the files for the MySQL database for `pawn.secondorder.pccc`.

- [Dockerfile](./pawndata/Dockerfile): The Docker file for the MySQL Server.
- [pawnshop.sql](./pawndata/pawnshop.sql): The schema file for the Pawn shop's MySQL database.
- [seed.sql](./pawndata/seed.sql): A short SQL file containing the initial seeding data for the Pawn shop's MySQL database.

### pawnShop

This directory contains the Flask application for the `pawn.secondorder.pccc` site. Note there are many files here, so details are provided only for the directories and critical files.

- [app](./pawnShop/app): This directory contains all of the source code for the Flask application.
  - [forms](./pawnShop/app/forms/): This directory contains the `Flask-WTF` classes used to create the various HTML forms on the site.
  - [models](./pawnShop/app/models/): This directory contains the `SQLAlchemy` classes used to load the data from the database, one per table in the database.
  - [static](./pawnShop/app/static/): This directory contains JavaScript, CSS, images, and any other static files (including the `uploads` directory for uploaded user files).
  - [templates](./pawnShop/app/templates/): This directory contains the templates that Flask uses to create the various pages.
  - [app.py](./pawnShop/app/app.py): This is the Flask app itself, containing all of the routes and the corresponding logic.
  - [db.py](./pawnShop/app/db.py): This Python script initializes the connections to the MySQL databases using ENV variables.
  - [warehouse.py](./pawnShop/app/warehouse.py): This is not executed and is just a copy of the warehouse [app.py](./warehouse/app/app.py). This file is referenced in a comment in the pawnshop `app.py`, allowing the competitor to also extract the warehouse source code.
- [Dockerfile](./pawnShop/Dockerfile): The Docker file for the Flask application.
- [entrypoint.sh](./pawnShop/entrypoint.sh): The entrypoint script used by the `Dockerfile`. Waits for the database to be available, loads Token 1 into the source code, and then launches the Flask app with `gunicorn`.
- [warehouse_id_rsa.pub](./pawnShop/warehouse_id_rsa.pub): A public key allowing the warehouse host to transfer files to the pawn host using `rsync`.

### proxy

A simple nginx proxy that exposes `pawn.secondorder.pccc` and `warehouse.secondorder.pccc` to the competitor.

- [Dockerfile](./proxy/Dockerfile): The Docker file for the nginx proxy.
- [nginx.conf](./proxy/nginx.conf): The configuration file for the nginx proxy.

### selenium

This container runs two scripts that use Selenium to simulate users viewing and interacting with the websites.

- [admin.py](./selenium/admin.py): The Selenium bot used to simulate an admin user denying cancellation requests for Token 3.
- [Dockerfile](./proxy/Dockerfile): The Docker file for the nginx proxy.
- [entrypoint.sh](./pawnShop/entrypoint.sh): The entrypoint script used by the `Dockerfile`. Waits for the databases to be ready, then runs `admin.py` and `spy.py` every 10 seconds.
- [laptop.webp](./selenium/laptop.webp): An image of an "old laptop with state secrets" uploaded by `spy.py`.
- [spy.py](./selenium/spy.py): The Selenium bot used to simulate the spy user viewing and creating auction items for Token 4.

### warehouse

This directory contains the Flask application for the `warehouse.secondorder.pccc` site. Note there are many files here, so details are provided only for the directories and critical files.

- [app](./warehouse/app): This directory contains all of the source code for the Flask application.
  - [forms](./warehouse/app/forms/): This directory contains the `Flask-WTF` classes used to create the various HTML forms on the site.
  - [models](./warehouse/app/models/): This directory contains the `SQLAlchemy` classes used to load the data from the database, one per table in the database.
  - [static](./warehouse/app/static/): This directory contains JavaScript, CSS, images, and any other static files (including the `uploads` directory for uploaded user files).
  - [templates](./warehouse/app/templates/): This directory contains the templates that Flask uses to create the various pages.
  - [app.py](./warehouse/app/app.py): This is the Flask app itself, containing all of the routes and the corresponding logic.
  - [db.py](./warehouse/app/db.py): This Python script initializes the connections to the MySQL databases using ENV variables.
  - [insertToken.py](./warehouse/app/insertToken.py): This Python script inserts Token 2 into the database when the docker container is launched.
- [Dockerfile](./warehouse/Dockerfile): The Docker file for the Flask application.
- [entrypoint.sh](./warehouse/entrypoint.sh): The entrypoint script used by the `Dockerfile`. Waits for the database to be available, loads Token 2 into the database using `insertToken.py`, runs a loop with `rsync` to copy any user-uploaded files to the pawn site, and then launches the Flask app with `gunicorn`.
- [warehouse_id_rsa](./warehouse/warehouse_id_rsa): A private key allowing the warehouse host to transfer files to the pawn host using `rsync`.

### warehousedata

Contains the files for the MySQL database for `warehouse.secondorder.pccc`.

- [Dockerfile](./warehousedata/Dockerfile): The Docker file for the MySQL Server.
- [warehouse.sql](./warehousedata/warehouse.sql): The schema file for the warehouse's MySQL database.
- [seed.sql](./warehousedata/seed.sql): A short SQL file containing the initial seeding data for the warehouse's MySQL database.

## Challenge Environment Initial Setup Requirements 

This challenge is run entirely using Docker and Docker compose, so start up is very straightforward.

### Installing Docker

First, install Docker and Docker compose, using the official docker instructions for whichever operating system you are using. The entire challenge can then be launched easily using 

`docker compose up -d`

TODO: Add any details about getting in? Maybe VNC?

### Grading

This challenge does not involve grading; all tokens are found on the site.