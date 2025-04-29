# Challenge Files README for c26: Keylogged

## challenge_files
The files located in the /challenge_files folder are files that were used to create part 2 of the challenge. They include a script to run the tcp client, a script to run the tcp server, and 6 files that represent keylogged data. 

## hosted_files
The files located in the /hosted_files folder are files that are hosted on the challenge server. 

1keyfileA.txt and 1keyfileB.txt are both used to acquire the first token. Players will need to analyze the content of these files to find a password that the keylogger captured.

The core.11066 is a core image of the keylogger process that was running on a victim machine. It shows the data that is stored in RAM as it is being keylogged. In this file is a password that the attacker typed in to access a C2 server. 

## Services

All services are configured to run on start using systemctl. 

`c2server.py` is running on 10.5.5.103 behind an nginx proxy.

`tcpclient.py` is running on 10.5.5.102

`tcpserver.py` is running on 10.5.5.101:8888

## startup

`startup.sh` runs on challenge server startup and is blocked by an HTTP check to `10.5.5.103/hidden_token_page`. It deletes all files in `/var/log/keylogs` on `10.5.5.103` and then runs a `curl` command to add token5 to `/var/log/keylogs` via an HTTP POST to the webserver. 

