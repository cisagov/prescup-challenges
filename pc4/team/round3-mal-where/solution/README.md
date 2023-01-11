# Mal-where?

_Solution Guide_

## Overview

Use the given security tools to discover the malware used to gain internal access to a user workstation.

## Question 1

_Who is the author of the malware?_

Examine logs to find a suspicious file then conduct malware analysis on it.

1. Review the "Background" and "Getting Started" sections of the challenge guide. Note the tools that are installed.
2. Launch the Wazuh Manager VM, browse to https://127.0.0.1, and view the various logs in Wazuh. This indicates the IP addresses and a few status logs from each machine.
3. Navigate to the PolarProxy machine. Viewing the `/etc/systemd/system/PolarProxy.service` showcases that the pcap files are stored in `/var/log/PolarProxy/`.
4. We know the incident occurred in early November. Change directory to `/var/log/PolarProxy` and run the command `ls` to view the pcap file and proxyflows. Here we see a `proxy-221102-010247.pcap` file that is 1.4G large. Transfer this to our Kali machine. One way to do this is to run the command `python3 -m http.server 8000` and on Kali browse to `172.13.14.1:8000`.
5. Download the  `proxy-221102-010247.pcap` file and open it in Wireshark. Feel free to split this pcap into three ~500MB pcaps with the command `tcpdump -r <proxy-221102-010247.pcap> -w <split-proxy-221102-010247.pcap> -C 500`.
6. There are various ways of finding a "starting point" of suspicious activity. One method is to click `Export Objects` > `HTTP` > `Save All`. Sifting through the thousands of decrypted objects will indicate a `login-prep` file.
7. Our pcap is ~1.4G, so will may decide to split it up. We would like to split the pcap up in 100MB chunks, run the command `tcpdump -r proxy-221102-010247.pcap -w split.pcap -C 100`. 
8. Open **split.pcap3** in Wireshark, search within `Packet bytes` the `String` `"login-prep"`. You should be taken to packet #30835 in `split.pcap3`.
9. Right-click packet #30835 and click `Follow` > `TCP Stream`.
10. Within this stream, we see it is an html file and there was a GET request for **yactf.com** (an unknown website). Save this stream as `login.html` (or any .html name; however, for the purposes of this solution guide we call it `login.html`).
11. Open`login.html` with a web browser.
12. We see:
    > To prepare your machine for this cutting-edge CTF, you must download the file below and run the commands
    > chmod +x login-prep
    > ./login-prep
    > Click to Download login-prep
    > Currently, we only support Linux-based OS for our challengers. We hope our next version supports others.
    > Powered by CTFd

	This is alarming as an internal IP address (**Alice**) downloaded the login-prep file and may have executed the recommended commands (`chmod +x login-prep` and `./login-prep`).
13. Find the `login-prep` file that was extracted previously. Run the command `file login-prep` within that directory to verify this is an executable. Not good!
14. Open this file with any text or hex editor. You will see who this malware was written by. This is the answer to Question 1.

## Question 2

_What is the IPv4 address of the C2 server?_

Examine proxy and access logs to discover the IP address of the C2 server involved after the malware was planted and executed. We must figure out who navigated to **yactf.com**. There are multiple ways to figure this out. In our original pcap, the source IP shows the squid proxy. 

1. Open the **squid-tcpdump** machine. `df -h` shows this machine is full; however, we won't let that stop us. Navigate to `/var/log/squid`.
2. Run the command `ls` to view the files.
3. `access.log.1` looks promising due to the Nov 2 timestamp. Run the command `sudo python3 -m http.server`. On Kali, browse to `http://10.5.5.1:8000` and download the file `access.log.1`. 
4. Open this file with your favorite text editor and notice that a search for `yactf.com` shows `10.5.5.101` (Alice) was the user who made the request to browse to yactf.com.
5. We need to see where Alice went after navigating to yactf.com; *that* may be the C2 server.
6. Run the command `sudo -i` on squid-tcpdump machine to gain root access. Navigate to `/root/pcaps/`.
7. Run the command `ls` to view the various pcap files. Run the command `python3 -m http.server`. On Kali, browse to `http://10.5.5.1:8000` and download the pcap files related to 2022-11-02. You can do this manually, or with a one-liner such as `for i in {0..3}; do for j in {0..9}; do wget http://10.5.5.1:8000/2022-11-02_01%3A02%3A42.pcap$i$j; done; done`
8. Filter out each pcap for traffic to or from Alice with the command `for i in *.pcap*; do tcpdump -r $i host 10.5.5.101 -w alice$i; done`.
9. Merge all Alice-related pcap files with the command `mergecap alice2022-11-02_01:02:42.pcap* -w all-alice.pcap`.
10. Open **all-alice.pcap** in Wireshark. Scrolling past the time after Alice downloaded `login-prep`, we see dozens of DNS lookups for `play.yactf.com`. That IP address is `139.144.21.181`. 
11. Navigate to `Statistics` > `Conversations` to further support that `139.144.21.181` has had a lengthy duration and number of packets between Alice and **play.yactf.com** (where we have already identified that yactf.com is malicious). `139.144.21.181`  is the answer to Question 2.

## Question 3

*Who was the attacker that was inside your network and left something behind?*

Discover the attacker who was inside your network based on artifacts left behind on the user workstation.

1. Navigate to Alice's workstation, **confidentcannon**. As noted: all web history, downloads, and command history has been wiped; however, remnants of the attacker still remain.
2. Navigate to the `/tmp` directory which contains a file called `forU.txt`. Run the command `cat forU.txt` and see "*I am still here @ CURRENT DATE*". Where did this log come from? How did it get updated to this current timestamp? 
3. Run the command `sudo find / -xdev -type f -print0 | sudo xargs -0 grep -H "forU.txt" 2>/dev/null` to search the string **forU.txt** across the entire filesystem.
4. Notice the file `/home/alice/.bashrc` has returned!
5. Open `/home/alice/.bashrc` with your favorite text editor.
6. Navigate through Alice's **.bashrc** file. You will see the echo command and a comment line with the name of the attacker who was on Alice's workstation. Please note that the attacker is different than the original malware creator. The answer to Question 3 is `PwningPaul`.
