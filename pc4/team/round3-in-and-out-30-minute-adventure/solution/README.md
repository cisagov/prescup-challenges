# In and Out, 30 Minute Adventure

_Solution Guide_

## Overview

To solve this challenge players must find the SMB share password, find the FTP server password, and delete a web file on a different part of the network. This solution guide is organized by challenge question. Get started by parsing the CSV to create a file that contains all possible website credentials. 

On the Desktop of the `user_1` and `user_2` VMs is a file containing records of all the people who might have an account on the target website. 
Accompanying it is a file explaining each user account is auto-generated using a specific process. Follow this process and create all possible credentials for each user in the file. Attached is an example [solution script](scripts/createWebCreds.py) that will generate a file with all possible credentials. 

## Question 1

_Find the SMB Share password._

You need to be on `link-insider` to start. First, set your IP to something within the `172.20.30.0/24` subnet. 

If you scan the FW1 using the command `nmap -Pn 172.20.30.1`, you will see ports `139` and `445` are open. This hints that SMB is running. Enumerate any information possible by running the following command: `enum4linux -USP 172.20.30.1`.

You should get the following information from this scan:
- there is a share hosted called `backup`
- there is one user named `tom`
- there is a comment on the share stating that the password has been set to **entry number #** in the list (**#** represents an actual number; and will change based on deployment).

On one of the `net3-insider` VMs: assign it an IP within the `220.133.91.0/24` range.

Start arpspoofing any traffic between the gateway `220.133.91.1` and the other machine on your network located at `220.133.91.202`. Following these steps:
1. Set your VM to do IP Forwarding so that when you spoof the traffic it still gets sent to its destination. Run the following command: `sudo bash -c "echo '1' > /proc/sys/net/ipv4/ip_forward"`.
2. Next, edit the `/etc/ettercap/etter.conf` file, updating it with these changes:
    - Ec_uid = 0
    - Ec_gid = 0
    - Uncomment the four (4) lines under the `Linux` section that pertain to applying iptables rules (should be lines # 179, 180, 183, and 184)
3. Run Ettercap in graphical mode (`sudo ettercap -G` in terminal) and follow these steps:
    - Click on the checkmark in the top right of the first screen that pops up to start Ettercap.
    - Click on the magnifying glass in top left to scan for hosts that are in your network.
    - Click the 3 dots in the top right, then select `hosts` -> `hosts list`
    - Select `220.133.91.1` and then click `Add to Target 1`
    - Select `220.133.91.202` and then click `Add to Target 2`
    - Click on the button that looks like a mini globe/world in the top-right area.
    - Click `ARP Poisoning`, make sure to disable all optional parameters, then start it.
4. Once running, open a second terminal and run Wireshark to start capturing traffic. You will see random `UDP` traffic being sent.
5. Right-click on the `UDP Packet` and then scroll down to `Follow` -> `UDP Stream`.
6. Within the packet that opens, you should have a small list of passwords mentioned in the `backup` share comment found previously.

The SMB password is the answer to Question 1.

## Question 2

_Find the FTP password._

On `link-insider`, connect to the SMB Share. See what shares are available using this command: `smbclient -L //172.20.30.1/`.

Using the credentials you've retrieved, connect to the listed share using this command: `smbclient -U "username%password" //172.20.30.1/backup`.

Within the share, you will find the following files:
- `ftpRotatingPwds`: This contains all possible passwords that might be set on the FTP server.
- `Fw1ConfigBak.xml`: Sift through this file to determine what rules are implemented on each interface.

On one of the `net3-insider` VMs: 

If you scan host `220.133.91.202` using the same `nmap` scan ran previously, you will see that the SSH port is open.

>Note: You will need to stop the arpspoofing in order to reach this host.

If you attempt to connect, you are prompted with a message stating that `anonymous` SSH is being used for configuration, has limited capabilities, and isn't intended for non-authorized users. It looks like a perfect location to find a vulnerability.

With the SSH User information retrieved, log into the SSH server using this command: `ssh anonymous@220.133.91.202`.

The FW1 config file shows that FTP traffic is allowed from `220.133.91.202` -> `210.111.90.123`, although if you attempt to connect using the `anonymous` user you will find that they do not have the permissions to run the commands.

Exploit the privilege escalation vulnerability present on the VM:

1. Run the command `sudo -l`.  You can see the account you are logged in as has no sudo permissions except for the command `find`. 
2. Run this command get a  root shell: `sudo find /home -exec /bin/bash \;`

You've seen FW1 config, and now with root privileges you have the ability to connect to the FTP server using the SSH server as your pivot point.

The `ftpRotatingPwds` has a message  stating it contains all possible passwords that could be implemented on the FTP Server. It also contains the SHA1 hash of the correct password as a backup - although it seems that the correct hash has been split up and randomized in an effort to prevent it to be easily discovered.

The FW1 config file shows that SSH traffic is allowed from the `link` network to the `220.133.91.202` VM where you now have root access. Transfer the `ftpRotatingPwds` to it, and then to one of your user VMs.

From here,  create all possible combinations of how the hash could be concatenated and compare all those possibilities against the hash of all the possible passwords in the file  to find the matching hash/password.

Attached is an example [solution script](scripts/findFtpHash.py).

The FTP password is the answer to Question 2.

Once found, you can download the following files from the FTP server:

- `FW2ConfigBak.xml`
- `Fw1Credentials`

## Question 3

_Log into the website and find the pin._

On a `Net1 user VM`:

Using the `Fw1ConfigBak.xml` file found earlier, you can see there is a dedicated IP range allowed to browse to the FW1 webpage over HTTPS: `200.99.113.1-200.99.128.1`.

Once you reconfigure IP to one within this range, you will be able to browse the following website `https://200.99.0.1`.

Now, you can log into the FW using the credentials found in the FTP Server. You can disable packet filtering or just create some "allow all rules on all interfaces" to permit all traffic to all interfaces.

If you analyze the `Fw2ConfigBak.xml`, you will see that the website is port forwarded from port `10.9.8.10:4040` -> `172.20.30.2:80` on the FW2. You will also see that all traffic is blocked to the port-forwarded site. There is also a misconfiguration; they blocked all traffic to the port-forwarded site but left an opening to reach the website directly from a specific IP range. HTTP Traffic from the IP range `200.99.130.1-200.99.140.1` bypasses the FW2 and can connect to the website. 

Once you get to the website, you will see the alien image being hosted. Begin by inspecting the website by right-clicking `inspect`. Click on the `Console` tab, and notice a leftover message from when they were creating the website. It mentions the URL `/admin/login`.  Browse to `10.9.8.10:4040/admin/login`.

With all the possible login credentials made, begin brute-forcing the website to determine the correct ones. Attached is a sample [solution script](scripts/bruteForceLogin.py) that will accomplish this. 

After successfully logging in, you should see a new page and a `pin` in the top left - make note of this. There is a `Files` page, and if you look on it, you will see the file you are trying to delete located at `/home/user/Desktop/site/static/intel.txt`. Although, you have no way of deleting it. 

The website has been left in `debug` mode, and because of this, the debug terminal is accessible. Browse to the page `10.9.8.10:4040/console` to see it. It asks for a pin in order to unlock it (you made note of this previously). Once you unlock it, you can run various commands through the website. 

The **pin** is the answer to Question 3,

The debug terminal acts as a python3 terminal, so you can run the following commands to remove the file:

- `import subprocess`
- `subprocess.run("sudo rm /home/user/Desktop/site/static/intel.txt",shell=True)`

If done correctly, you can browse back to the website main page and you will see the intel document is no longer there.

## Question 4

_Browse to `https://200.99.5.5` and begin the grading check. You will be presented with a hex token upon successful completion._

Upon successfully removing the file, browse to `https://200.99.5.5` and click the **grade** button. If you have removed the file, you are presented with a hex string. The hex string is the answer to Question 4 and is the final token for this challenge. 
