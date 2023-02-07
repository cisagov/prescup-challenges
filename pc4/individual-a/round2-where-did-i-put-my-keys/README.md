# Where did I put my keys?

A devastating insider threat attack has disabled a critical cube drive manufacturing facility. You are tasked with helping us regain SSH access to the file server. 

**NICE Work Roles**
- [Cyber Defense Incident Responder](https://niccs.cisa.gov/workforce-development/nice-framework/work-roles/cyber-defense-incident-responder)

**NICE Tasks**
- [T0510](https://niccs.cisa.gov/workforce-development/nice-framework/tasks/t0510) - Coordinate incident response functions.
- [T0278](https://niccs.cisa.gov/workforce-development/nice-framework/tasks/t0278) - Collect intrusion artifacts (e.g., source code, malware, Trojans) and use discovered data to enable mitigation of potential cyber defense incidents within the enterprise.


## Background

On August 16, a high-ranking employee in charge of securing many of our servers has shut down our access to a cube drive manufacturing facility's main server. 

The attacker left an encrypted attack script alongside every other employee’s SSH key pairs. We believe the attacker used one of the collected SSH key pairs to encrypt a python script using 256-bit AES and cipher-block chaining. To prevent further compromise, we reset the SSH keys used for authentication. 

Additional evidence shows the attacker was using the `ssh-access` workstation and the username `remote-user` to upload `python` or `shell` scripts to `ftp-server.us`. The scripts were automatically executed upon upload. 

The image below shows the connections we suspect the attacker is capable of making. 

![network-topology-1258573180.png](https://launchpad.cisa.gov/tm/docs/f37bd01778b445d3938a090d0139c73a/connection-map-945403253.png)

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