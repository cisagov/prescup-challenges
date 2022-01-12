# Transmission Control Problems Solution

The solution guide will be broken into sections which describe how to find the answer to each of the following PCAP files: `synflood.pcapng`, `nmap_scan.pcapng`, `shrew_attack.pcapng` and `telnet.pcapng`.  

This solution guide shows screenshots from Variant 1 of the challenge. The process for solving the challenge will remain the same, while the IP Address answers will differ for each challenge version.  

## SYN Flood Solution

1. Open the pcap file `synflood.pcapng` in Wireshark  

2. Look for TCP SYN Packets in the capture. By scrolling through the file, the host that is sending a lot of SYN packets should be obvious in the grey-colored packets. See the screenshot below for an example of what to look for. 

   <img src="img/image1.png">

The IP address that is sending the SYN packets is the answer for the PCAP.

## Answer  

```
 10.89.32.124
```

## Port Scan Solution

1. Open the file `nmap_scan.pcapng` in Wireshark
   
2. Use the navigation bar at the top of the window to select `Statistics > Conversations` to view all of the TCP conversations that appear in the file  

3. You should see 1 IP address that is initiating a lot of conversations with another host on a lot of different ports. This is the indication of port scanning to look for. An example is shown in the screenshot below. 

   <img src="img/image2.png">

The IP address that is performing the port scan is the answer for the PCAP. 

## Answer 

```
10.206.234.42
```


## Shrew Attack Solution

1. Open the file `nmap_scan.pcapng` in Wireshark  

1. Recall from the suggested research paper about the Shrew Attack that the attack is an attack which will use short bursts of network traffic to create temporary congestion. The attacker will start a low of new flows to fill the network flow buffer. The attacker does this by sending a lot of packets in a short amount of time (burst). Because of this attack strategy, we should look for IP addresses which are sending short bursts of data at a high data rate. 

1. Use the navigation bar at the top of the window to select `Statistics > IPv4 Statistics` to view information about all of the IPv4 connections in the file. In this view, look for the two hosts which have the shortest burst time, or as Wireshark denotes it "Rate (ms)". This column will show how long (in ms) a flow typically lasts. Long burst times are indicative of continuous communication, whereas the short bursts are going to show short-lived flows. Another field to examine is what Wireshark calls the "Burst Rate". This field shows about how many packets were sent during the time interval (1ms in this case).  The indicator of a Shrew Attack will be the combination of a low "Rate (ms)" field and a high "Burst Rate" field in Wireshark. This will be hosts which are sending a lot of short-lived flows. 

1. The screenshot below shows an example of this window.

   <img src="img/image3.png">

1. Investigate the two IP Addresses which have the shortest burst times in the capture. Notice that the two IP Addresses are communicating only with each other. The UP address which began the communication (i.e. the IP address out of those two which is the first to send a packet) is the answer to submit for this section. 

## Answer 

```
10.206.234.42
```

## Unencrypted Traffic Solution

1. Open `telnet.pcapng` in Wireshark.

2. We are looking for the password for the telnet service. Trying to filter the traffic for only telnet traffic (Enter the display filter `telnet` in Wireshark) does not yield any packets -- The answer must be within the TCP/UDP/HTTP traffic that is in the PCAP file. 

3. Looking at the first packet, right click and follow the TCP/UDP steam.  If there seems to be a bunch of random characters as part of the stream, filter this stream out with the display filter `!<proto>.stream == #` where `<proto>` is replaced with `tcp` or `udp` and `#` is replaced with the stream number. You can chain filter phrases with the `and` keyword

4. When you come across TCP Stream 2 (For Variant 1 -- number might differ for other versions), notice that the data in the stream is readable text. It appears to be a conversation between 2 people about telnet credentials. One party says the credentials are stored on the web server with IP Address `10.5.5.75`.

5. We should begin to look for HTTP traffic now. Enter a display filter to only view HTTP packets (`http` is the display filter).

6. Notice a GET request for a file titled `telnet`. You can save this file by clicking `File > Export Objects > HTTP` and saving the file which is in the web response. 

7. Look in the bytes of the HTTP Response which contains the `telnet` file. Notice the "magic number" in the file header -- `50 4B 03 04 [PK]`. This indicates the that file should have a `.zip` extension. Save the file with this extension when you export the object. 

8. Inside the zip file is a plaintext file with the username on the first line and the password on the second line. Enter the password for the submission. 

## Answer

```
7b467b4af0daae10
```


