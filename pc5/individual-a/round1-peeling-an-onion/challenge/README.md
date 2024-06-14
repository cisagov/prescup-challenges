# Peeling an onion

_Challenge Artifacts_

The included PCAP file can be used to answer the questions in for the challenge in lieu of setting up the complex environment hosted on the archive site.  The description of the environment setup is described below with the scripts used to generate the pcap included in the respective sfolders.


[attacker](./attacker/) - This machine has several scripts running as services to attack the website running on webserver1 from 3 different IPs simulating separate machines.  The [namespaces.sh](./attacker/namespaces.sh) and [traffic.py](./attacker/traffic.py) are set to run as services at startup. The 2 wordlists are used to generate unsuccessful and successful brute force attempts.

[webserver1](./webserver1/) - This machine runs the [startup.sh](./webserver1/startup.sh) script as a service at startup which calls the [dbseed.py](./webserver1/dbseed.py) script to add accounts to the database.  This machine was running the "deliberately insecure web application" docker container website that was vulnerable to the attacks scripted in the `namespaces.sh` script.  The container used for the webserver is available [here](https://github.com/snsttr/diwa)


[webserver2](./webserver2/)- This machine runs the [webserver.py](./webserver2/webserver.py) script at startup to generate traffic from the traffic script.
