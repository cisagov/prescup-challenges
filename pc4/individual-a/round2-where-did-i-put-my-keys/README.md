# Where did I put my keys?

A devastating insider threat attack has disabled a critical cube drive manufacturing facility. You are tasked with helping us regain SSH access to the file server. 

**NICE Work Roles**
- [Cyber Defense Incident Responder](https://niccs.cisa.gov/workforce-development/nice-framework)

**NICE Tasks**
- [T0510](https://niccs.cisa.gov/workforce-development/nice-framework) - Coordinate incident response functions.
- [T0278](https://niccs.cisa.gov/workforce-development/nice-framework) and use discovered data to enable mitigation of potential cyber defense incidents within the enterprise.

## IMPORTANT

This challenge only partially open sourced. The files in the [challenge directory](./challenge) are provided to give you a starting point if you wish to recreate the challenge on your own. 

Please follow the instructions in the [challenge directory](./challenge) to setup the required files before attempting to play this challenge offline.  

The files provided/generated will allow you to solve Question 1. The full version of the challenge can be played on the hosted site.  

## Background

On August 16, a high-ranking employee in charge of securing many of our servers has shut down our access to a cube drive manufacturing facility's main server. 

The attacker left an encrypted attack script alongside every other employee’s SSH key pairs. We believe the attacker used one of the collected SSH key pairs to encrypt a python script using 256-bit AES and cipher-block chaining. To prevent further compromise, we reset the SSH keys used for authentication. 

Additional evidence shows the attacker was using the `ssh-access` workstation and the username `remote-user` to upload `python` or `shell` scripts to `ftp-server.us`. The scripts were automatically executed upon upload. 

The image below shows the connections we suspect the attacker is capable of making. 

![network-topology.png](./img/network-topology.png.png)

## Getting Started

You’ve been given access to our`kali-workstation` and credentials to `user` on `ftp-server.us`. The FTP access you are given contains the resources you need.

We need you to: 
1. Determine which SSH key pair was used to encrypt the attacker's script. Use the decrypted script to login to the `ssh-access` machine. 
2. Utilize the `ssh-access` machine to login to the `ftp-server` using the `remote-user`.
3. Use the access you gained to login to the `secure-server` and retrieve the token.

## Challenge Questions

1. Which user's key was used to encrypt the script?
2. What is the token found on the ftp server?
3. What is the token found on 10.5.5.128?
