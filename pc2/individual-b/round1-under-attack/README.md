# Under Attack

Intercept a brute-force login attempt in real-time to discover details behind the attack. Familiarity with SSH, C++, and make is expected.

**NICE Work Role:**

- [Exploitation Analyst](https://niccs.cisa.gov/workforce-development/nice-framework)
- [Software Developer](hhttps://niccs.cisa.gov/workforce-development/nice-framework/workroles?name=Software%20Developer)

**NICE Tasks:**  
- [T0009](https://niccs.cisa.gov/workforce-development/nice-framework)  - Analyze information to determine, recommend, and plan the development of a new application or modification of an existing application
- [T0500](https://niccs.cisa.gov/workforce-development/nice-framework) - Modify and maintain existing software to correct errors, to adapt it to new hardware, or to upgrade interfaces and improve performance.


## Setting Up
   
  
  Before beginning this challenge, you will need to make sure to put the folder **"challenge"** on your VM's desktop for this challenge to run properly. Once that folder is on your desktop, go ahead and follow the next steps to finish setting up this challenge: 
  
  - Navigate to the [challenge](challenge/) directory with the following command: 
  ```
  cd ~/Desktop/challenge/
  ```
  and change access permissions to the [setup.sh](challenge/setup.sh) shell script to make it executable. You can do this by writing the command below on your VM's terminal: 
  ```
   chmod +x setup.sh
   ```

   - Once the [setup.sh](challenge/setup.sh) shell script has the right access permissions, you can go ahead and execute it with the following command:
  
   ```
   ./setup.sh
   ```
   - This is going to prompt you for your VM's password and, once entered, it will download some necessary packages in order to apply important factors needed to achieve this challenge. 
   
   - ***Note: The [setup.sh](challenge/setup.sh) shell script and the [brute.py](challenge/brute.py) python script were not provided in the actual competition, instead, they are going to be used just once to set up your environment for this challenge. Seeing the contents written inside the [setup.sh](challenge/setup.sh) shell script and the [brute.py](challenge/brute.py) python script will spoil the answers for this challenge, so it is best to avoid interacting with the [setup.sh](challenge/setup.sh) shell script and the [brute.py](challenge/brute.py) python script aside from the commands mentioned before.** 

   - Once your the [setup.sh](challenge/setup.sh) shell script finishes, you are good to begin this challenge.

## Background

SSH brute force attacks are a low-effort means for criminals to find accessible systems to use for nefarious purposes. They use dictionaries of common usernames, passwords, and default credentials
and target huge swaths of the Internet looking for susceptible machines.

Your incident response team has identified suspicious inbound SSH traffic. As an exploitation specialist, the team has asked you to modify the local ssh daemon in order to gain insight into the attacker's password library. This will help protect against similar attacks in the future.

## Getting Started

Log in to your Xubuntu workstation. In the `~/Desktop/challenge/` directory, there will be a .tar.gz file containing the ssh server software source code. Your task is to modify, compile, and install a new daemon that logs, prints, stores, or otherwise saves the passwords provided by the users attempting to connect to the system.

In a real world scenario, the attacker's password dictionary could consist of thousands of unique passwords. This exercise is different, and the attacker has a password dictionary with only one entry. Retrieve the password to complete this challenge.

You will need root access to install your modified ssh daemon. Use `sudo su` to elevate to root privileges.

## Submission Format

The submission for this challenge is an 8-byte value represented by 16 hexadecimal digits. All letters will be upper case.

