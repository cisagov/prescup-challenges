# Indicative Solution

## Challenge Overview

This challenge involves network traffic analysis of a PCAP file. You must identify a specific threat from a PCAP which contains malicious activity.  You are tasked with finding the IP address which has been targeted by a code execution exploit for Trendnet IP Cameras.  There is 1 attacker IP address. The rest of the IP addresses are the devices on your network. 

 

## Hints

Hint 1: Find the attacker's IP address. Look at SYN Packets and the IP that is the Source IP of most conversations.  

Hint 2: The attack is on a CGI form on a website hosted on port 80.  

Hint 3: You're looking for a Command Injection exploit. Look for "cmd=" in the URL query.  

## Steps to Solve

Open the PCAP in Wireshark.  

There are several ways to identify what the attacker’s IP address is. 
The first way is to look for SYN Packets. Most (if not all) of the SYN packets should be coming from the attacker because they will be starting connections to try to exploit the service.   
Another way is to look at the Wireshark conversation statistics. Go to Statistics > Conversations.  Notice the source of most of the conversations is the same. 
These two ways should give you the same indication that the attacker’s IP address is 172.28.254.72.  

Now that we know the attacker’s IP, we can move forward with finding the particular attack that we are interested in. We are looking for a code execution attack on a Trendnet Camera.   
A search for how to use or setup Trendnet IP Cameras will show that there is a web interface on the device using port 80. We also know that the request should be coming from our attacker’s IP address. We can setup a display filter to only show traffic from 172.28.254.72 that is destined for port 80. Apply another filter to show only HTTP traffic. The display filter should look like this:  
`ip.src == 172.28.254.72 && tcp.dstport == 80 && http`  

Looking at the requests left over by this filter, it appears as though a lot of requests are for a Microsoft product. Since we are looking for a Trendnet product, we can filter out the Microsoft results by adjusting the display filter: 
`ip.src == 172.28.254.72 && tcp.dstport == 80 && http && not http contains "Microsoft"`    

This still leaves a lot of packets in the display window.  

Looking online, you can find several trendnet camera emulators from their website. Use some of the emulators and inspect the source code of the web pages by right clicking the web page and selecting "View Page Source".  

There are a number of references to CGI (Common Gateway Interface) applications on the Trendnet emulator pages. Add this to the display filter:
`ip.src == 172.28.254.72 && tcp.dstport == 80 && http && not http contains "Microsoft" && http contains ".cgi"`    

After this filter, there are only about 300 packets and only 2 destination IP addresses. One of the destination IP addresses only appears one time in the filtered data.

View the HTTP request that was received by the IP address that only appears once as the destination IP address in this filtered data.  The HTTP query is `GET /cgi/maker/ptcmd.cgi?cmd=;ls"`.  Search this query online and find that this is an exploit for Trendnet IP cameras. Submit the IP address that received this query as the flag. 







