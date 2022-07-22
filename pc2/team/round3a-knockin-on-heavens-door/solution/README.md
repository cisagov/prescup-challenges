# Knockin' On Heaven's Door Solution

## Part 1 - Analysis

Use Wireshark to capture on the eth0 interface of the Kali machine. It will take some time to gather
enough data to complete the lab. The attacker is using port knocking to open four different ports
on the victim machine, then downloading a file each time. The attack runs in a loop, so first it hits
host0, then host1, then host2, and finally host3 before looping back around to host0.

Each host runs on a randomly assigned port and has a different knock pattern that is randomly assigned
when the challenge is launched. The length of the knock pattern is not random:

host0: 3 ports

host1: 4 ports

host2: 3 ports

host3: 5 ports

## Part 2 - Solve

There are three types of traffic relevant to this challenge: False knocks that do nothing, real knocks 
that open ports, and file transfers. Each real knock will be immediately followed by a file transfer of
several megabytes. This should give enough information to copy the knock and connect to the listening
service. There may be up to 7 minutes between interesting events. There will be one set of false knocks
between each file transfer, so if you see more than 5 knocks prior to the download, check timestamps
to find the divide between false knocks and real knocks.

Use nmap to knock the required sequence in order to open the port:

```
for x in 10412 10826 18112; do nmap -Pn -host-timeout 201 -max-retries 0 -p $x 192.168.1.100; done
```

Once the knock is complete, immediately use your web browser to open an SSL connection to the port
opened by the knock. The port will only remain open for about 5 seconds. This will reveal an Apache
directory listing. The .zip file is being exfiltrated and the .txt file represents proof that the
participant completed this portion of the challenge.

As an added frustration, the hosts must be accessed in order. Once host0 has been opened, it cannot
be opened again until hosts 1, 2, and 3 have been opened in order.

## Part 3 - Submission

All four .txt files must be retrieved in order to complete the challenge. Note that the .txt file for
host3 is obscured. The Apache-generated index.html file is not actually generated in real-time, but is
a cached version with modified links. The link named SuBmIsSiOn.TxT actually points to the file
sUbMiSsIoN.tXt, which does NOT conform to the same format as the other solution files. The participant
is expected to discover this and manually retrieve SuBmIsSiOn.TxT directly, without using the link.

It is also necessary to download each .zip file and extract it so that the correct submission token
can be associated with the correct input on the challenge submission form.


<br>
<br>



## Detailed step by step: 

DO THIS AS SOON AS THE LAB LAUNCHES. QUICKER IS BETTER TO ENSURE THAT ALL MALICIOUS TRAFFIC IS SEEN

`open kali console`

`open terminal`

```
sudo su 
```

`password is tartans`

`wireshark`

`double-click eth0`

Let wireshark run for like 20 minutes or so. there will be four large file downloads, then all processes will repeat.

Set filter to ip.src == 192.168.1.100

There will be a pattern of traffic with some SYN packets (4-7, typically) followed by a large amount of TLS traffic. The last SYN packet is the TLS connection initiation. The ones immediately preceding it are the knock pattern. note the timestamps, though, as the attacker also makes some garbage knocks to confuse anyone watching. if there is a break longer than a few seconds, disregard the SYN packets because the knock window is very short.

The knock ports are random, so it is necessary to check the traffic each time the challenge is attempted. in my case, the first attack traffic has knocks at 19521, 14244, and 44037, followed by TLS traffic on port 5704. after the first attack but before the second, there are meaningless knocks. there is a buffer before/after the bad knocks of about 180 seconds. the second attack has knocks at 41222, 19851, 52139, and 30638. The TLS traffic is on port 6778. next is another round of silence, bad knocks, and silence, followed by the third knock. Mine was 36112, 28048, 11570, and TLS traffic on 8829. silence, bad knocks, silence. Fourth knock sequence was then 39539, 12372, 26263, 34968, 46170. TLS traffic at 8311. note that, after the bad knocks, the process will repeat the first attack and loop continuously.

The knock sequences have different lengths. Two consist of three ports, one of four ports, and one of five ports.

Note that, while not apparent in the traffic, the service listening for knocks will only listen for one knock pattern at a time. Once that pattern has been entered, the next pattern is enabled and the old one disabled. The TLS ports will ONLY be opened in the sequence shown in the captured traffic. As a result, when attacking the service, if the scripted attacker opens a port successfully, the participant will have to skip to the next one. Then the scripted attacker will fail and, if the participant does nothing, will not be successful in opening any ports until its internal loops go around to the listening port again.

Nmap apparently doesn't work fast enough on kali, so to knock ports write a python script:

```
#!/usr/bin/python3
import socket
for port in ( 19521, 14244, 44037 ):
    sock = socket.socket( socket.AF_INET, socket.SOCK_STREAM )
    sock.settimeout( 0.1 )
    result = sock.connect_ex( ( '192.168.1.100', port ) )
    sock.close()
```

Write four scripts, one for each knock sequence.

You can either figure out where in the sequence the knock service is by watching the wireshark traffic, or just spam the knock scripts (in order) to open the service ports. Use your browser, make sure the URL has https (not http), and specify the port that will be unlocked next in the sequence. The linux/firefox/signal/xfce submissions are tied to the files the attacker is stealing, so you will need to download each .zip file in order to make these associations. The submission token is stored in a file with some variant of the name "submission.txt" be careful on one of them - the index.html is not autogenerated. I copied the auto-generated html and modified it to point to a decoy file, but the name printed to screen is the correct name.