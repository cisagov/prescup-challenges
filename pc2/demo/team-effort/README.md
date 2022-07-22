# Team Effort

Find the target IP and SSH port. Connect and grab token. Easy!



**NICE Work Role:**   

- [Cyber Defense Analyst](https://niccs.cisa.gov/workforce-development/nice-framework/workroles?name=Cyber+Defense+Analyst&id=All)

**NICE Tasks:**
- [T0299](https://niccs.cisa.gov/workforce-development/nice-framework/tasks?id=T0299&description=All) - Identify network mapping and operating system (OS) fingerprinting activities.

## Setup
For this challenge you'll need to two virtual machines on a the 192.168.33.0/24 subnet (one must be Ubuntu VM). Move the files in the challenge folder into the Ubuntu vm and run the startup.sh file. When ran this should update your netplan and ssh configurations so that you have a new IP address and port number for that IP address.

## Background  
Your team is looking for a remote box's IP, SSH port, and a file within its user's home directory.

## Getting Started
Find the target IP (it is on the 192.168.33.0/24 subset). Find the target's port SSH is running on (HINT: it's not port 22). Connect to the target with creds below. Read the contents of ~/token.txt on the target system. Submit tokens. Easy!

## Submission Format
Example submission:  

**Last Octet IP**
```
254
```

**Port SSH is Running On**
```
1024
```

**Token Found in ~/token.txt**
```asdfghjk\n```
