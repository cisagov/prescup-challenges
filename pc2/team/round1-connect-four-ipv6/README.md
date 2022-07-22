# ConnectFour (but with IPv6)

Your team must use several systems to connect to three unique IPv6 interfaces and services after performing the proper network configuration, discovery, and enumeration tasks. Once each connection is made, an answer file for each can be found on the remote system. Additionally, the team must use one of these connections to reconfigure a service in order to allow a new connection. Once that final connection is made to the remote system, a fourth and final answer file can be found and the challenge is complete. Teams must use a combination of Windows and Kali Linux systems to make these connections.

**NICE Work Role:**
- [Network Operations Specialist](https://niccs.cisa.gov/workforce-development/nice-framework/workroles?name=Network+Operations+Specialist)

**NICE Tasks:**
- [T0029](https://niccs.cisa.gov/workforce-development/nice-framework/tasks?id=T0029&description=All) - Conduct functional and connectivity testing to ensure continuing operability.

- [T0081](https://niccs.cisa.gov/workforce-development/nice-framework/tasks?id=T0081&description=All) - Diagnose network connectivity problem.

- [T0129](https://niccs.cisa.gov/workforce-development/nice-framework/tasks?id=T0129&description=All) - Integrate new systems into existing network architecture.  

- [T0144](https://niccs.cisa.gov/workforce-development/nice-framework/tasks?id=T0144&description=All) - Manage accounts, network rights, and access to systems and equipment.

- [T0232](https://niccs.cisa.gov/workforce-development/nice-framework/tasks?id=T0232&description=All) - Test and maintain network infrastructure including software and hardware devices

## IMPORTANT
There are no downloadable artifacts for this challenge. The full challenge can be completed on the hosted site.

## Background
Three systems have been hidden on your network. Each system available to you shares a network with one of these hidden systems. You must discover these systems on each of the three different systems/networks, find an open service, and make three unique connections. Once you have made all 3 connections, you will be able to assemble the password for a new user with elevated privileges. With this new user account, you can access a hidden system to further reconfigure a service to allow a new connection from a new user. The catch: these hidden systems only listen and respond over IPv6 and your systems have no current network configuration. You only have the following networking information and the various scanning and enumeration tools at your disposal.

## Getting Started
1. Perform network discovery from each system in order to discover the IPv6 address of the hidden system. Each team system will only find one hidden system out of the 3 total, one per network. These beacons will always come from an **2002:aaaa:bbbb:cccc:dddd:eeee:xxxx:xxxx** type address.

2. Configure the various team systems for their proper IPv6 addresses based on the following guidance. All addresses will have the form **2002:aaaa:bbbb:cccc:dddd:eeee:xxxx:xxxx** where you must find the proper values for the final two hextets.
    
    ***- Configure Windows10-A:***
    
    *The system used to be set with an IPv6 configuration of 2002:aaaa:bbbb:cccc:dddd:eeee:0a64:0a19/126. This address is correct, but something else is wrong that will prevent your connection from going through.*
    
    ***- Configure Kali:***
    
    *Convert the IPv4 address of 172.16.60.198/30 to an IPv6 address where an IPv4 address of 10.100.25.50 would be 2002:aaaa:bbbb:cccc:dddd:eeee:0a64:1932 (simply converting the IPv4 octets to hex for the values of the final 2 hextets). You should use a IPv6 subnet mask that maintains the number of allowed hosts from the previous IPv4 value (i.e. /24 allows 256 hosts in IPv4…what mask also allows for 256 hosts when using IPv6).*
    
    ***- Configure Windows10-B:***
    
    *Find the hidden system's IPv6 address first. Then apply the first available host on the same subnet when applying a subnet mask of /115, i.e. the host that is furthest from the hidden system within that subnet. Sometimes this connection can take a while to return a command prompt after logging in.*


3. Enumerate/scan each hidden system in order to find an open service to connect to. The hidden system will reject all attempts to connect over IPv4 and also reject attempts that are not coming from the specific IPv6 address or range of addresses expected.
  	
    On Windows10-A use **UserA/tartans** to connect.  
    On Kali use **UserB/tartans** to connect.  
    On Windows10-B use **UserC/tartans** to connect.  
                  
4. Once connected from each system, look in the landing directory for an answer file and 1/3 of UserD’s password. You will not be able to browse to other directories with these user accounts or run restricted commands. Each of these answer files provides 1 out of 4 answers for the challenge.

5.	Use one of the previous three methods to connect using UserD’s password. Only one will work.

6.	Use this account to reconfigure the SSH service so that UserE can also connect from Windows10-A with its current address. You will have limited administrative privileges when using sudo and the password \"tartans\". If you cannot run a specific command it is not one that you need.

7.	Once connected as UserE via SSH, the final answer file will be found in the landing/home directory.

## Winning Conditions
In order to win the challenge, all steps above must be completed and the team must find all four answer files on the remote system. Each answer file is worth 25% of the overall point value for the challenge.

## Submission Format
Each submission is a 12 character string made up of numerals and lowercase letters. No lowercase L's are used, only numeral 1's, to avoid confusion between the two.

## Hints
You may use online IP/subnet calculation tools and perform research for the proper scanning syntax.
Creating hosts file entries for the hidden systems will reduce typing and makes connections faster.

