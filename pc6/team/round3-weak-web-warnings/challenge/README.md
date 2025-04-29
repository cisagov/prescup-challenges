# WWW (Weak Web Warnings)

*Challenge Artifacts*

This README file contains details on how the challenge was created and how it could be recreated in a different environment. 

### Website

This directory contains the source code and configuration files for the three Docker containers that make up the website. 
Should contain two empty directories used for persistent storage by the database Docker container: `storage/db` and `storage/logs`.

- [docker-compose.yml](./website/docker-compose.yml): Contains the Docker configurations for the three containers.

#### db

Contains configuration files for the MySQL database.

- [db.sql](./website/db/db.sql): A short SQL script that builds the database tables and inserts the default data. Run once when the database is initially built.
- [my.cnf](./website/db/my.cnf): A configuration file enabling logging for errors and all queries that are executed.
  - Errors are logged in the persistent `./storage/logs` directory so they are accessible between database builds.
- [mysqld.sh](./website/db/mysqld.sh): Replaces the usual MySQL daemon start script so that error logging is passed to stdout (and thus accessible to Docker).

#### proxy

Contains the configuration files for the Apache proxy based on https://github.com/dhmosfunk/CVE-2023-25690-POC

- [Dockerfile](./website/proxy/Dockerfile): Dockerfile used to build the Apache proxy; loads the `httpd.conf` file into the correct location in the container.
- [httpd.conf](./website/proxy/httpd.conf): Enables mod_rewrite and the proxy settings in Apache such that `CVE-2023-25690` is possible. The proxy is directed to the container in the [web](./website/web) directory.

#### web

Contains the source code and configuration for the actual site in PHP.

- [src](./website/web/src/): Contains the website source code
  - [alerts.php](./website/web/src/alerts.php): Loads and prints the alerts from the database; vulnerable to SQLi
  - [envHandler.php](./website/web/src/envHandler.php): A simple class that retrieves env values; prints the HTTP smuggling token and used for the PHP Object Injection
  - [hosts.php](./website/web/src/hosts.php): Prints a static table of hosts; vulnerable to PHP Object Injection and contains the token found in a comment
  - [index.php](./website/web/src/index.php): Calls include on the user input page; vulnerable to source code leakage via PHP include
  - [token.php](./website/web/src/token.php): If visited, creates a file called "success.txt" so the `envHandler` knows the HTTP smuggling token should be printed
  - [token.txt](./website/web/src/token.txt): Contains the token to be retrieved after the HTTP smuggling attack is successful
- [Dockerfile](./website/web/Dockerfile): Configures an Apache server with PHP by moving config files and the source code
- [httpd.conf](./website/web/httpd.conf): Directs Apache logging to stdout/stderr so they can be seen via Dockers logging
- [logging.ini](./website/web/logging.ini): Directs PHP logging to stdout/stderr so they can be seen via Dockers logging

### Scripts

These are various scripts or files used during setup or grading.

- [start.py](./scripts/start.py): The start up script used by `challenge.us`. Uses Python's `Paramiko` module to SSH into `web.us` and place dynamically generated tokens. The Docker containers are then rebuilt and redeployed.

## Challenge Environment Initial Setup Requirements 

This challenge is run entirely using Docker and Docker compose, so start up is very straightforward.

### Installing Docker

First, install Docker. On Ubuntu Server, the original OS used for `web.us`, this can be done with the following commands from [docs.docker.com](https://docs.docker.com/engine/install/ubuntu/):

```bash
sudo apt-get update
sudo apt-get install ca-certificates curl
sudo install -m 0755 -d /etc/apt/keyrings
sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
sudo chmod a+r /etc/apt/keyrings/docker.asc

# Add the repository to Apt sources:
echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu \
  $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
  sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
sudo apt-get update
sudo apt-get install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
```

### Building and Running

Now to run the challenge, first navigate to the folder containing the [docker-compose.yml](./website/docker-compose.yml) file. Use docker compose to start the containers. Note you may need to create the empty storage directories first.

```bash
mkdir storage
mkdir storage/db
mkdir storage/logs
docker compose build  # Build the containers
docker compose up -d  # Run in the background
```

That's all that should be needed. The server should now be accessible in your browser at `web.us` or the server's IP address.

### Grading

This challenge does not use a grading script. However, it does have an optional [start up script](./scripts/start.py) that is used to place dynamically generated tokens inside the website source code and docker files.

## Cover Tracks

Prior to saving the server templates, clear the history to prevent competitors from reviewing any previously run commands. 
 
```bash
history -c && history -w
```
