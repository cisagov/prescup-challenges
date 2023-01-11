# Why is the R&D Always Gone?

Gain research and development intel by hacking the Followers' router and production systems.

**NICE Work Roles** 
- [Cyber Operator](https://niccs.cisa.gov/workforce-development/nice-framework/work-roles/cyber-operator)

**NICE Tasks**
- [T0768](https://niccs.cisa.gov/workforce-development/nice-framework/tasks/t0768) - Conduct cyber activities to degrade/remove information resident in computers and computer networks.
- [T0696](https://niccs.cisa.gov/workforce-development/nice-framework/tasks/t0696) - Exploit network devices, security devices, and/or terminals or environments using various methods or tools.

### NOTE

***This challenge can take about eight (8) minutes to launch and configure. You may see intermittent router activity within this timeframe.***

## Background

You have gained an initial foothold in the Followers' research and development infrastructure and now you want to get increased access to this R&D facility. Intel suggests there is a chat server and a file server (via SSH) on the Followers' internal production subnet. Intel also suggests there is a user network that accesses the production subnet. 

Obtain access to the production subnet systems by completing the three tasks below and answering the three questions. Intel suggests Followers use standard usernames and have provided a password wordlist on your Kali VM via ISO. 

## Getting Started

Exploit the router (172.21.3.1) and manipulate it to gain access to the production network. Gain access to the filesystem and chat messages. Cowrie has been downloaded to your Kali system; however, minor configurations may be required.

- **Task 1:** Exploit the router; gain access to its underlying OS; alter the router to access the internal production subnet.
- **Task 2:** Gain access to the filesystem by capturing and using SSH credentials. 
- **Task 3:** Read the chat messages on the chat server.

## Questions

1. Gain access to the router's underlying OS. What username, besides root, is on this OS?  
2. A username periodically logs into the SSH file system. What is this user's password?  
3. Gain access to the chat server messages. What temperature must the vaccine be stored at?  

## Note

Installing packages from `apt` and `pip` repositories is not supported in this challenge.