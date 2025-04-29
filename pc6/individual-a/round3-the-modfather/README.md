# The ModFather

A company is looking for a third-party solution to secure their Modbus devices, but they remain unprotected in the meantime! The company has found an outdated implementation of a Open Platform Communications Unified Architecture (OPC UA) server on GitHub built using the `node-opcua` library. Get the code running and add simple authentication.

**NICE Work Roles**

- [Network Operations](https://niccs.cisa.gov/workforce-development/nice-framework/)
- [Secure Software Development](https://niccs.cisa.gov/workforce-development/nice-framework/)

**NICE Tasks**

- [T0077](https://niccs.cisa.gov/workforce-development/nice-framework/): Develop secure code and error handling.
- [T1019](https://niccs.cisa.gov/workforce-development/nice-framework/): Determine special needs of cyber-physical systems.
- [T0129](https://niccs.cisa.gov/workforce-development/nice-framework/): Integrate new systems into existing network architecture.
- [T1313](https://niccs.cisa.gov/workforce-development/nice-framework/): Test network infrastructure, including software and hardware devices.

## Background

The OPC UA standard provides a standardized and more secure interface for communicating data between industrial machines/devices and the cloud. Use the provided Kali machine to protect a Modbus device with an OPC UA server by debugging an old open source implementation.

## Getting Started

An audit revealed that a major industrial company has been exposing their Modbus devices to the cloud. This behavior is critical for their day-to-day operations, and they cannot reach an agreement with a third party vendor to provide software. In the meantime, the company has set up a DMZ and found a simple, open source implementation of an OPC UA server for a Modbus device.

The company has provided you with a Kali machine with access to all of their networks. The DMZ contains the OPC UA Server (`10.7.7.2`) and the Modbus device (`10.7.7.3`). You have been provided with SSH access to the OPC UA server and access to their firewall. A network diagram is provided below and can also be downloaded from `https://challenge.us/files` from your Kali machine.

![A network diagram showing 3 segments named DMZ, LAN, and WAN. They are joined by a router, with a firewall protecting the LAN and DMZ. The Kali box has a different interface connected to all three segments. The LAN also has the challenge.us server. The DMZ also contains a modbus device with IP address 10.7.7.3 and the OPCUA Server with IP address 10.7.7.2.](challenge/artifacts/network.png "Network Diagram for 'The ModFather'")

The OPC UA server (`10.7.7.2`) contains an `opcua` directory with `server.js` and `modbushandler.js` files, which are no longer compatible with the `jsmodbus` library. To edit the files, you can use SSH or VS Code to remote into OPC UA server (note you may want to turn of VS Code's `auto indent` setting to paste into VS Code and/or paste in smaller segments if your internet connection is slow). The server can be run with `node server.js`.

The Modbus device has been configured by company; you do not need to edit the `config.json` file. They have also already installed all of the node modules you will need.

Finally, you can use the `uaexpert.AppImage` executable for a graphical interface (see README in home directory). Alternatively, the `wan_client.js` script in the Kali home directory can be used to test the OPC UA server.

## Submission

There are 4 tokens to retrieve in this challenge. Each token is a 12-character hexadecimal value. The tokens all require a grading check from `http://challenge.us`. After running the grading check, that grading attempt's stdout/stderr will be available to download from `challenge.us` under the hosted files. 

- Token 1: Configure NAT rules on the pfSense firewall to allow WAN access to the OPC UA server on port `8080`. 
    - As the OPC UA server is not yet running, run `nc -l 8080` on the OPC UA server before grading at `http://challenge.us`.
- Token 2: Fix the code on the OPC UA server to allow read access to the non-boolean registers available on the Modbus device. The `config.json` file already contains the correct parameters for the modbus device. In the interest of time, the issues to fix are listed below:
    1. In `modbushandler.js`, update `modbus.client.tcp.complete` and `this.modbusclient.on` to use the new `jsmodbus` API.
    2. In `modbushandler.js`, the response when polling the Modbus device has changed; update the file to correctly access the values.
- Token 3: Fix the issue with boolean registers, allowing read access to all registers on the Modbus device. 
    - When reading values in `modbushandler.js`, the `node-opcua` module now strictly expects a boolean value, not a "truthy/falsy" value.  
- Token 4: Add a username and password requirement to the fixed OPC UA server. Use `user` and `tartans` as the username and password (password can be stored in plaintext in `server.js`).

## System and Tool Credentials

|system/tool|username|password|
|-----------|--------|--------|
|kali-modfather|user|tartans|
|OPC UA Server - 10.7.7.2|user|tartans|
|pfsense - `https://pfsense.merch.codes`|admin|tartans|

## Note

Attacking or unauthorized access to `challenge.us` (10.5.5.5) is forbidden. You may only use the provided web page to view challenge progress and download any challenge artifacts that are provided.