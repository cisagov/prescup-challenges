# Interstellar Intrusions

Perform external network reconnaissance, service identification, and various exploitation tasks to gain access to systems within a spacehip's network.

**NICE Work Roles**

- [Exploitation Analyst](https://niccs.cisa.gov/workforce-development/nice-framework)
- [Vulnerabiltiy Assessment Analyst](https://niccs.cisa.gov/workforce-development/nice-framework)

**NICE Tasks**
 - [T0028](https://niccs.cisa.gov/workforce-development/nice-framework): Conduct and/or support authorized penetration testing on enterprise network assets.
 - [T0570](https://niccs.cisa.gov/workforce-development/nice-framework): Apply and utilize authorized cyber capabilities to enable access to targeted networks.


## IMPORTANT
This challenge does not have any downloadable artifacts. You may complete this challenge in the hosted environment.

## Background

Compromise several rival spaceship systems to retrieve sensitive information. You have access to the perimeter of their network, but you have limited knowledge about the type and location of each system.

## Getting Started

You've been given Kali workstations on the WAN network to the ship's firewall and a DHCP address within the `123.45.67.100-123.45.67.110` IP range.

Perform standard network reconnaissance tasks to determine pathways into the network through the firewall. Review the vulnerability and exploit materials found in-game at `https://challenge.us`. Them, determine which vulnerabilities and exploits apply, and use the supporting files and information accordingly. Discovering which method(s) apply to each machine is part of the challenge.

>**Note:** It may take a few minutes for the firewall to distribute your DHCP address and for all services within the environment to come up fully. Please be patient!

## Objectives

Each objective can be completed independently.

### Objective 1: Gain access to the DMZ Server (non webserver) in the 10.7.7.0/24 network

A standard server is running in the DMZ. Gain root access to the server and retrieve the contents of `/root/token1.txt`.

### Objective 2: Gain access to the DMZ Webserver in the 10.7.7.0/24 network

A webserver is running in the DMZ. Gain root access to the server and retrieve the contents of `/root/token2.png`.

### Objective 3: Successfully phish and reverse shell to the system in the 10.1.1.0/24 network

*Due to triggering requirements, this task has a few conditions. Please read the following before attempting this objective*

Browse to `https://mail.merch.codes` in-game and register for an account. Make sure you use the string "it-admin@merch.codes" as the Email address and "it-admin" as your username. *You can only do this once*.

Prepare and send a phishing email to `user@merch.codes` with these parameters:
- A URL in the message that points to `http://yourfiles.zip`, but has the text of `yourfiles.zip`; implying you are sending an important file, but it is actually a link.
- The **Subject** and other text can be whatever you like.

Create an appropriate .elf payload file and set up an interface, payload hosting webserver, listener, etc., on Kali to gain a reverse shell to the user's system *when the `http://yourfiles.zip` page is clicked*. Internal DNS is pre-configured to map `http://yourfiles.zip` to `123.45.67.150:80` for you. The target is a Linux x86_64 system.

Go to `https://challenge.us` and run the grading check to validate that the sent email is present and contains the required items. The check then triggers the user system to visit your malicious site at `http://yourfiles.zip` (123.45.67.150), download your payload file, and execute it. If all is correct, you will receive your reverse shell.

*Note that your payload will only run for a maximum of 30 seconds and each successive initiation of the grading check will kill and then delete any previous payload that was downloaded.*

The flag will be found at `/home/user/token3.txt` once you have a shell.

### Objective 4: Gain access to the 10.2.2.0/24 network server

A standard server is running in the 10.2.2.0/24 network.

The `token4.txt` file will be discoverable in the process of solving this part of the challenge, but you will need to determine how to access it. 
