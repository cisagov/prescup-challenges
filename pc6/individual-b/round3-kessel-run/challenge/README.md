# Kessel Run

*Challenge Artifacts*

This README file contains details on how the challenge was created and how it could be recreated in a different environment. 

### Artifacts

This directory contains the files provided to the competitor

- [proxies_provided](./artifacts/proxies_provided/): This directory contains copies of the proxy source code with empty template HTML files; see [proxies](#Proxies)
  - [proxies_provided/run.sh](./artifacts/proxies_provided/run.sh): A bash script for running all four proxies simultaneously with logging
- [KesselRun.drawio](./artifacts/KesselRun.drawio): An XML save file from [draw.io](https://draw.io) that was used to created the network diagram
- [KesselRun.png](./artifacts/KesselRun.png): An image displaying how the proxies are set up and interact with each other 

#### proxies

Each of the following directories are used as docker volumes in the `docker-compose` file.

- [channel](./proxies/channel/): Contains the files for the `channel` proxy. Mounted as a volume in the `channel` docker container.
  - [channel.html](./proxies/channel/channel.html): An HTML file with text describing the `channel`.
  - [channel.py](./proxies/channel/channel.py): The `channel` proxy source code, designed to proxy to `maelstrom`. Vulnerable to CL.TE HTTP smuggling.
  - [token.html](./proxies/channel/token.html): An HTML file with some flavor text; does not contain a token and instead directs the competitor to work towards `maelstrom`.
- [maelstrom](./proxies/maelstrom/): Contains the files for the `maelstrom` proxy. Mounted as a volume in the `maelstrom` docker container.
  - [maelstrom.html](./proxies/maelstrom/maelstrom.html): An HTML file with text describing the `maelstrom`.
  - [maelstrom.py](./proxies/maelstrom/maelstrom.py): The `maelstrom` proxy source code, designed to proxy to `maw`. Vulnerable to TE.CL HTTP smuggling.
  - [token.original.html](./proxies/maelstrom/token.original.html): An HTML file with some flavor text; the start-up script uses this file to create `token.html`, replacing `TOKEN` with the actual token value 
- [maw](./proxies/maw/): Contains the files for the `maw` proxy. Mounted as a volume in the `maw` docker container.
  - [maw.html](./proxies/maw/maw.html): An HTML file with text describing the `maw`.
  - [maw.py](./proxies/maw/maw.py): The `maw` proxy source code, designed to proxy to `kessel`. Vulnerable to CR.LF HTTP request splitting/smuggling.
  - [token.original.html](./proxies/maw/token.original.html): An HTML file with some flavor text; the start-up script uses this file to create `token.html`, replacing `TOKEN` with the actual token value
- [kessel](./proxies/kessel/): Contains the files for the `kessel` proxy. Mounted as a volume in the `kessel` docker container.
  - [kessel.html](./proxies/kessel/kessel.html): An HTML file with text describing the `kessel`.
  - [kessel.py](./proxies/kessel/kessel.py): The `kessel` server source code; this is the final server and does not act as a proxy.
  - [token.original.html](./proxies/kessel/token.original.html): An HTML file with some flavor text; the start-up script uses this file to create `token.html`, replacing `TOKEN` with the actual token value
- [docker-compose.yml](./proxies/docker-compose.yml): The docker-compose configuration file for the four proxies and their networks. The containers log to `systemd`.  

### Scripts

The scripts or files used during setup or grading.

- [start.py](./scripts/start.py): The start-up script used by `challenge.us`. Uses Python's `Paramiko` module to SSH into `channel.us` and place the dynamically generated tokens. As these are mounted Docker volumes, there is no need to restart the containers.

## Challenge Environment Initial Setup Requirements 

This challenge is run entirely using Docker and Docker compose, so start up is very straightforward.

### Installing Docker

First, install Docker. On Ubuntu Server, the original OS used for `channel.us`, this can be done with the following commands from [docs.docker.com](https://docs.docker.com/engine/install/ubuntu/):

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

Now to run the challenge, first navigate to the folder containing the [docker-compose.yml](./proxies/docker-compose.yml) file. Use docker compose to start the containers.

```bash
docker compose build  # Build the containers
docker compose up -d  # Run in the background
```

That's all that should be needed. The server should now be accessible in your browser at `channel.us`.

### Grading

This challenge does not use a grading script. However, it does have an optional [start-up script](./scripts/start.py) that is used to place dynamically generated tokens inside the website source code and docker files.

## Cover Tracks

Prior to saving the server templates, clear the history to prevent competitors from reviewing any previously run commands. 
 
```bash
history -c && history -w
```
