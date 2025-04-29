# The ModFather

*Challenge Artifacts*

This README file contains details on how the challenge was created and how it could be recreated in a different environment. 

### Challenge design

This challenge is a bit different from the usual types of challenges in that it requires the competitor to fix an open source server implementation, so I wanted to discuss a little about why that is here. The motivation for this challenge was to approach ICS from a defensive viewpoint. How can we configure and secure ICS devices? 

However, most recommendations for securing ICS devices fall into one of three categories: 1) upgrade to or purchase a more secure device/protocol, 2) pay a third-party vendor for a centralized auth/monitoring device, or 3) build one yourself. The first two (while the most realistic) are not possible for us. The goal, then, was to find an open-source implementation and have the user configure it. Turns out, there are not a lot of good OPC UA implementations out there for free as they can be quite difficult to build and generally require hardware to test properly.

I found one [implementation](https://github.com/minaandrawos/OPCModbusUAServer) and the original goal was to have the competitor configure it. Well, it turned out that the configuration would be either incredibly simple, or overwhelmingly complex and needing too much specialized knowledge. However, when setting up the server, it turns out the original developer did not include the version of `jsmodbus` in the `packages.json` file, so the code did not run and I needed to spend time debugging it to get it working. This became the challenge. 

To succeed, the competitor needs to have some intermediate level knowledge of debugging, programming, and NodeJS, and some beginneer level knowledge of networks/firewalls. The ICS is now flavoring around that skillset, and the challenge instead introduces them to concept of OPC UA servers, rather than requiring them to already be familiar with it.

### artifacts: 

These are provided as part of the challenge instructions. 

- [network.drawio](./artifacts/network.drawio): A network diagram created using [draw.io](draw.io) to inform the competitor of their network access (not provided).
- [network.png](./artifacts/network.png): The previously mentioned network diagram exported as a PNG, included in the challenge instructions.

The user was also provided with a copy of ["UaExpert—A Full-Featured OPC UA Client"](https://www.unified-automation.com/products/development-tools/uaexpert.html) in the Kali machine's home directory.

### modbus

These files are used on the modbus server to simulate a Modbus device.

- [modbus.js](./modbus/modbus.js): The `nodejs` code that uses the `jsmodbus` module to simulate a Modbus TCP server.
- [package.json](./modbus/package.json): The `npm` packages required to run the above `nodejs` code.

### opcua

These files are provided on the opcua server for the competitor to fix and run a OPC UA server. The code is adapted from [this Github repo](https://github.com/minaandrawos/OPCModbusUAServer).

- [config.json](./opcua/config.json): Defines the configuration for the server, including the Modbus registers that should be read. This is pre-configured to work with the Modbus server.
- [LICENSE](./opcua/LICENSE): The standard MIT license that was part of the repo this was based on.
- [local_client.js](./opcua/local_client.js): This is a copy of the [wan_client.js](./scripts/wan_client.js) script used for grading, but using a local IP address. Provided on the opcua server as a means of testing the server locally if desired.
- [modbushandler.js](./opcua/modbushandler.js): The `nodejs` code that handles reading the Modbus device.
- [package.json](./opcua/package.json): The `npm` packages required to run the `nodejs` code.
- [server.js](./opcua/server.js): The `nodejs` code that creates the OPC UA server instance and calls the `modbushandler`. This is the file to run with `node server.js`.

### scripts

These are various scripts or files used during setup or grading.

- [grader.py](./scripts/grader.py): The grading script used by `challenge.us`. Checks that `123.45.67.2:8080` is available and then parses the output from the OPC UA server by calling [wan_client.js](./scripts/wan_client.js).
- [interfaces](./scripts/interfaces): The network interfaces that are loaded onto the Kali machine when [./startup.sh](./scripts/startup.sh) runs. Adds the Kali machine to the DMZ and WAN interfaces on eth0 and eth1.
- [readme.txt](./scripts/readme.txt): Loaded into the home directory of the Kali machine when [./startup.sh](./scripts/startup.sh) runs. Describes how to use [wan_client.js](./scripts/wan_client.js) and the UAExpert OPC UA Client.
- [startup.sh](./scripts/startup.sh): Runs when `challenge.us` starts and copies various files from `challenge.us` to the Kali machine.
- [wan_client.js](./scripts/wan_client.js): A `nodejs` script that connects to the OPC UA server, reads the required values, and prints them. Loaded onto the Kali machine at start up as well. Uses the same [package.json](./opcua/package.json) from the opcua server.

## Challenge Environment Initial Setup Requirements 

### Setting up the Modbus "Device"

The Modbus "device" is really just a low-resource Ubuntu server with a barebones `jsmodbus` server installed as a service.

First, download the [modbus](./modbus/) files to the home directory and install the required packages.

```bash
sudo apt install npm
sudo npm install -g n
sudo n install stable # Make sure we have the most recent version of node
npm install .
```

Now register it as a service using the following config.

```none
[Unit]
Description=Modbus simulator server
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/node /home/user/modbus.js
WorkingDirectory=/home/user
StandardOutput=journal
StandardError=journal
Restart=on-failure
User=user

[Install]
WantedBy=multi-user.target
```

Finally, enable the service.

```bash
sudo systemctl enable modbus
```

### Setting up the OPC UA Server

Set up is very similar to the modbus server.

First, download the [opcua](./opcua/) folder to the home directory and install the required packages.

```bash
cd opcua
sudo apt install npm
sudo npm install -g n
sudo n install stable # Make sure we have the most recent version of node
npm install .
```

That's it for this one as the competitor will need to run the service.

### Grading

The grading script uses nmap to make sure that port 8080 is open.

```bash
sudo apt install nmap
```

The grading script runs [wan_client.js](./scripts/wan_client.js), so we also need to install node for that. Copy [package.json](./opcua/package.json) from the `opcua` folder and then run the following.

```bash
sudo apt install npm
sudo npm install -g n
sudo n install stable # Make sure we have the most recent version of node
npm install .
```

Run the grading script when grading is needed. 

## Cover Tracks

Prior to saving the server templates, clear the history to prevent competitors from reviewing any previously run commands. 
 
```bash
history -c && history -w
```
