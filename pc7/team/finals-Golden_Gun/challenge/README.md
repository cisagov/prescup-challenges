# Golden Gun

*Challenge Artifacts*

This README file contains details on how the challenge was created. 

### mazeSolverProd

Contains the PHP maze solver application.

- [app/index.php](./mazeSolverProd/app/index.php): The (only) source code file for the PHP application. Note this version contains logging not present in the version provided to the competitor.
- [db_seed.py](./mazeSolverProd/db_seed.py): Places the second token in the database for the user to retrieve.
- [Dockerfile](./mazeSolverProd/Dockerfile): The Dockerfile used to build the container.
- [entrypoint.sh](./mazeSolverProd/entrypoint.sh): Runs `db_seed` until it succeeds, then starts the Apache server.

### mazeSolverLocal

Contains a copy of the PHP maze solver application that the competitor can access.

- [app/index.php](./mazeSolverLocal/app/index.php): A copy of the original PHP application but with logging removed.
- [Dockerfile](./mazeSolverLocal/Dockerfile): The Dockerfile used to build the container.

### mysql

A MySQL database container that contains the second token.

- [Dockerfile](./mysql/Dockerfile): The Dockerfile used to build the MySQL DB container.
- [init.sql](./mysql/init.sql): Creates and places some sample data (not the token) in the database.

## Challenge Environment Initial Setup Requirements 

This challenge is run entirely using Docker and Docker compose, so start up is very straightforward.

### Installing Docker

First, install Docker and Docker compose, using the official docker instructions for whichever operating system you are using. The entire challenge can then be launched easily using 

`docker compose up -d`

TODO: Add any details about getting in? Maybe VNC?

### Grading

This challenge does not involve grading; all tokens are found on the site.