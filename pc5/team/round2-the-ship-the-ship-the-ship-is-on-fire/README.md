# The Ship, The Ship, The Ship is on Fire

Regain control of a damaged spaceship by using various networks, protocols, and interfaces to intercept, alter, and create the required network traffic.

**NICE Work Roles**

- [Cyber Defense Analyst](https://niccs.cisa.gov/workforce-development/nice-framework)
- [Software Developer](https://niccs.cisa.gov/workforce-development/nice-framework)

**NICE Tasks**

- [T0291](https://niccs.cisa.gov/workforce-development/nice-framework): Examine network topologies to understand data flows through the network.
- [T0023](https://niccs.cisa.gov/workforce-development/nice-framework): Characterize and analyze network traffic to identify anomalous activity and potential threats to network resources.
- [T0176](https://niccs.cisa.gov/workforce-development/nice-framework): Perform secure programming and identify potential flaws in codes to mitigate vulnerabilities.


## Background

The ship's main control console has been damaged by a collision with space debris and the resulting fires. We can't control multiple systems using  traditional interfaces and we need your help. Take control of the ship using any means necessary to get the crew and its cargo home safely!

## Getting Started

Read the *Submission Details* below which provide additional information to help locate the four tokens for this challenge. Each team member should start by logging into their Kali VM. The Kali VMs contain many of the tools necessary to regain control of the ship.

If you use **Security Onion** to complete this challenge, it may take 5 to 8 minutes after launching the challenge to become available.

If you use **Security Onion** to create PCAP files, make sure to enter `securityonion` in the `Sensor ID` field. Log into Security Onion at `10.4.4.4` through a browser or via SSH.

## Submission Details

There are four (4) tokens to retrieve in this challenge. Review the additional information about each token.

### Token 1

The GPS system is broadcasting the destination coordinates every 15 seconds to the GPS receiver. Unfortunately, the interface to update the coordinates has been damaged. Figure out a way to spoof the signal coming from the receiver and update the coordinates to `32.943241, -106.419533`. You can check your progress by going to `http://10.3.3.97/Home/GPS`. 

### Token  2

Our communications antenna isn't working. Reposition it to a new satellite to begin receiving data. Because the ship is damaged, the CAN bus can't be accessed via the usual physical interfaces. However, access via remote monitoring console allows data to be sent and received. 

The `python-can-remote` package has been installed on the Kali VMs, allowing communication with the server via web sockets. The current system sends encoded CAN Bus data from `10.1.1.183` to `10.3.3.223` using an arbitration id of `0xa1223a`. View the traffic, decode it, then look at the CAN Bus messages. 

To reposition the antenna: increase each of the existing values of the antenna (arbitration id of `0xa1223a`) by 11 (in decimal). E.g.:  if the existing data values transmitted are `[11, 22, 33, 44, 55, 66, 77, 88]`, you should transmit updated values of `[22, 33, 44, 55, 66, 77, 88, 99]` from your Kali VM to `10.3.3.223`. Be sure to transmit the data using an arbitration id of `0xa1223a`.

Use the in-game example `https://challenge.us/files/remote-can-bus.txt` to write a Python script using `python-can-remote` to adjust the antenna. 

Additional documentation can be found online here: `https://github.com/christiansandberg/python-can-remote`. It is recommended to broadcast the data using roughly the same time interval as the existing transmissions. Once you begin repeatedly transmitting the data to `10.3.3.223` from your Kali VM, run the grading script to check the results.

### Token 3

The ship's damage control console is reporting that a fire has broken out onboard! Unfortunately, we can't control the ship's systems from the console. Log into the damage control console at `http://10.7.7.119` to determine which rooms are alarming.  

- The rooms that are on fire will have smoke alarms tripped and temperatures above the normal room temperature of 70 - 78 degrees F.
- Isolate the rooms on fire by activating the doors to close them off from the rest of the ship. Then, activate the fire suppression system.  
- Shuttles (marked on **Ship_diagram.png**) have sensors for smoke and temperature, but do not their own fire suppression. You can leave the door open between the adjacent room and activate the fire suppression system in the adjacent room.  
- Fire suppression will not activate if the room is not isolated.  
- Shuttles do not need to be isolated. You can use the doors of neighboring rooms to isolate them. 

When the fire suppression systems have been activated, go to: `https://challenge.us` to retrieve the token. 

**A map of the ship (*Ship_diagram.png*) containing rooms and systems can be found here: `https://challenge.us/files`.**

### Token 4

An application "under development" is rumored to repeatedly send a message over the network using WebSockets. Find the token and submit it as the as the answer to Question 4. Please note that the data transmitted for this part of the challenge will not contain CAN Bus data and is not related in any way to the data used to answer Question 2.

## Challenge Questions

1. What is the token that was revealed at `http://10.3.3.97/Home/GPS` after altering the GPS coordinates?
2. What is the token revealed on `http://challenge.us` after modifying the CAN Bus data for the antenna system?
3. What is the token revealed on `http://challenge.us` after activating the fire suppression system?
4. What is the token embedded in the WebSocket data?