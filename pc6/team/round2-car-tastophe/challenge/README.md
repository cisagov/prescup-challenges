# Car-tastrophe

*Challenge Artifacts*

This README file contains details on how the challenge was created and how it could be recreated in a different environment. 

### artifacts: 

These are provided to the competitor via the Files capability of the Challenge Server. 

- [Twig_canmsgs.xlsx](./artifacts/Twig_canmsgs.xlsx): An excel spreadsheet from the [open source community](https://github.com/dalathegreat/leaf_can_bus_messages) with minor simplifications defining the CAN bus message formats/purposes.
- [Twig_canmsgs.pdf](./artifacts/Twig_canmsgs.pdf): A PDF copy of the CAN bus messages.
- [readme.txt](./artifacts/readme.txt): A simple txt file adding some additional details, including a link to where the PCAP files can be downloaded, an example of connecting to the CAN bus with python-can, and notes about the `Twig_canmsgs` files.

### canServer: 

- [server.py](./server/): A simple Python server that sends CAN bus messages at regular intervals. The [server](./canServer/server.py) loads a list of CAN devices from [devices.py](./canServer/devices.py).

- [devices.py](./canServer/devices.py): Contains the implementations of the devices listed in [Twig_canmsgs.xlsx](./artifacts/Twig_canmsgs.xlsx)

- [runTCPDump.py](./canServer/runTCPDump.py): As Wireshark does not currently have a socketcand dissector, this script uses tcpdump to capture CAN bus messages, which are exposed for download using nginx.

### scripts: 

These are scripts on the Challenge Server which faciliate challenge grading. 

- [grader.py](./scripts/grader.py): The scipt called by the Challenge Server when the "Grade Challenge" button is pressed. It connects to the server running the canServer and
    1. queries the Twig API for the AC status for task 1, and
    1. checks the file `ac_status.json` for the current state of the A/V climate system and brakes for tasks 4 and 5. 

- [apiRevealer.py](./scripts/apiRevealer.py): A Python script ran as a service to continuously request the Twig API, allowing the competitor to discover the API endpoints. 

### twig-api

- [api.py](./twig-api/api.py): A Flask application that implements the Twig API based on data extracted by the [open source community](https://github.com/jdhorne/pycarwings2). The API is largely static, returning pre-defined JSON snippets.

- [Dockerfile](./twig-api/Dockerfile): The Dockerfile used to build the Flask application. Built using `docker buildx build . -t twig-api` and ran with `docker run -d -p 8080:8080 --restart always twig-api`. Nginx was used to expose the service on port 80 as `twig-api.merch.codes`.

- [generateRandomTrips.py](./twig-api/generateRandomTrips.py): Ran during the Docker build, this creates a set of trips that can be downloaded from the API.

## Challenge Environment Initial Setup Requirements 

### Setting up the canServer

First, install can-utils on the Ubuntu Server, which can be done using `sudo apt install can-utils`.

Next, set up a virtual CAN interface and enable it:

```bash 
sudo ip link add name vcan0 type vcan && sudo ip link set dev vcan0 up
```


There are many different ways to automatically launch this at boot time, but I simply used a systemd service:

```none
[Unit]
Description=SocketCAN interface vcan0
After=multi-user.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStartPre=-/bin/ip link add name vcan0 type vcan 
ExecStart=/bin/ip link set dev vcan0 up 
#ExecReload=/bin/ip link set dev vcan0 down && /bin/ip link set dev vcan0 up
#ExecStop=/bin/ip link set dev vcan0 down

[Install]
WantedBy=multi-user.target
```

To test that it is working, run the following commands in two different terminals:

```bash
# Listens on the vcan0 interface and prints any broadcasted messages. Run this first and leave running.
candump vcan0 
# Sends 112233 using ID 123 on the vcan0 interface
cansend vcan0 123#112233
```

The CAN server can now run locally, but is not exposed to other devices on the network. That requires socketcand. Install the necessary packages, clone the socketcand repo, and then build it:

```bash
sudo apt install make git gcc autoconf libconfig-dev linux-headers-$(uname -r)
git clone https://github.com/linux-can/socketcand.git
cd socketcand
./autogen.sh
./configure
make
sudo make install
```

The install should add a socketcand systemd service to start on boot, but you can launch it manually if needed.

The final step before running the server is to install the requirements.

```bash
pip install python-can apscheduler
```

Make sure the `server.py` and `devices.py` files are in the same directory, then start the server:

```bash
python3 server.py
```

Note you may need to change some of the directories in the source code to match your system.  To run the server as service, you can use the following systemd service:

```none
[Unit]
Description=Canbus Server
After=multi-user.target

[Service]
User=user
Group=user
WorkingDirectory=/home/user
#ExecStartPre=/usr/bin/sleep 60
ExecStart=/usr/bin/python3 server.py

[Install]
WantedBy=multi-user.target
```

#### Optional tcpdump service

If you want to use Wireshark to analyze the packet captures from runTCPDump.py, first install tcpdump and tshark:

```bash
sudo apt install tcpdump tshark
```

Now you can either run the script directly, or set up a service like the one below. Note you may need to change some directory names again to match your system.

```none
[Unit]
Description=Canbus tcpdump

[Service]
User=user
Group=user
WorkingDirectory=/home/user
ExecStartPre=-/bin/bash -c 'rm /home/user/captures/*.pcap /home/user/capt_in_progress/*.pcap;/usr/bin/true'
ExecStart=/usr/bin/python3 runTCPDump.py

[Install]
WantedBy=multi-user.target
```

Expose the PCAPs for download using nginx with the following settings:

```none
server {
	listen 5000;

	server_name 123.45.67.2;

	root /home/user/captures;

	autoindex on;
}

```

### Setting Up the Twig API

In the challenge, this is done on the same Ubuntu server as the canServer, but could be different if you like.

To set it up, simply build and run the Docker file with `api.py` and `generateRandomTrips.py` in the same directory.

```bash
docker buildx build . -t twig-api
docker run -d -p 8080:8080 --restart always twig-api
```

Finally, expose the Flask app using the following nginx proxy settings.

```none
server {
	listen 80;

	server_name twig-api.merch.codes;

	location / {
		proxy_pass http://127.0.0.1:8080;
	}
}
```

### API Revealer and Grading

The API revealer is a simple python script run on `challenge.us`, which only needs the package `apscheduler`.

```bash
pip install apscheduler
```

Either run the script in the background, or enable it as a systemd service.

```none
[Unit]
Description=Twig API Revealer
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=user
WorkingDirectory=/home/user/challenge/scripts
ExecStart=python3 /home/user/challenge/scripts/apiRevealer.py
Restart=on-failure

[Install]
WantedBy=multi-user.target
Alias=apiRevealer.service
```

The grading script uses paramiko to connect to the canServer VM.

```bash
pip install paramiko
```

The grading script wants to log to `/var/log/challengeGrader/gradingCheck.log`. Create the folder and assign the correct permissions, or change the log file to somewhere writeable.

```bash
sudo mkdir /var/log/challengeGrader
sudo chown user /var/log/challengeGrader
sudo chgrp user /var/log/challengeGrader
```

Run the grading script when grading is needed. The grading script works by

1. SSHing into the canServer VM and making a request to the Twig API for the AC status (SSH is done to avoid "leaking" to the eavesdropping pfSense box), and
2. SSHing into the canServer VM and reading the `ac_status.json` file, which is created by the canServer and contains the state of the A/V climate status and the brakes.

## Cover Tracks

Prior to saving the server templates, clear the history to prevent competitors from reviewing any previously run commands. 
 
```bash
history -c && history -w
```
