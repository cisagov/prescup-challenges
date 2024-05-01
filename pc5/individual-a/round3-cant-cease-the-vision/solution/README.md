# Can't Cease The Vision

*Solution Guide*

## Overview

*Can't Cease The Vision* requires the competitor to identify how insiders send an 8-digit launch code across closed-circuit television (CCTV) streams.

Please keep in mind that reading this solution guide *before* attempting the challenge will lead to the false notion that this challenge is easy to solve.

## Question 1 & 2

*The 8-digit launch code is sent using various destination ports. What is the numerically highest destination port used in this transaction?*
*What is the 8-digit launch code?*

1. On the Kali machine, navigate to `10.4.4.4` and log into Security Onion.
2. Click **PCAP**, then click  ‘**+**’  to **Add Job**. 
   - **Sensor ID**: securityonion
   - **Filter Begin** and **Filter End**: cover the range of time the challenge is deployed (e.g., **Filter Begin** 2023-09-08 12:00:00 and **Filter End** to 2023-09-08 13:00:00) 
3. Click **Add**.
4. When Status is **Completed**, click the **binoculars**, then the **download icon** to download the pcap.
5. Open the pcap with Wireshark.
6. Click **File**, **Export Objects**, and **HTTP** to see files that Wireshark can easily extract from the pcap file. 

7. From here, change the **Content-Type** on the top-right from **All Content-Types** to **application/octet-stream**. 

8. Now, you will extract one octet-stream related to the IP `10.1.1.20` and port `8000`. To do so, type `8000` on the **Text Filter** field. This will only show octet-streams related to port 8000. Select one of them and click on `Save`. Save it as **8000.file**. You will repeat these steps for port `8008`, `8080`, `8088`, and `8888`. Save them as **8008.file**, **8080.file**, **8088.file**, and **8888.file**. 


9. Open a terminal and browse to the files you just saved. Run the commands below to discover the type of file each file is. The data is MPEG transport stream data.

```bash
file 8000.file
file 8008.file
file 8080.file
file 8088.file
file 8888.file
```

10. Run the commands below to open each file and view the stream.

```bash
open 8000.file
open 8008.file
open 8080.file
open 8088.file
open 8888.file
```

Competitors may choose to run the `binwalk` command or perform other forensics on these network streams; however, nothing unauthorized is happening here. The video streams are all expected parts of the dam and no other data is hidden within.

11. Re-examine the network traffic for other traffic not related to these five authorized CCTV streams. In Wireshark, click **Statistics**, **Conversations**, and **IPv4**. Here we see a different IP address `10.1.1.10` communicating with `10.2.2.20` with a large number of packets. Click **Close**.

12. Search all traffic for packets containing the IP address of `10.1.1.10` by applying *ip.addr == 10.1.1.10* as a display filter. We see a lot of UDP traffic over ports 25, 53, 67, 68, 69, and 123; however, the Info fields inform the competitor that this traffic is malformed, unknown, etc.
13. Update your search to *ip.addr == 10.1.1.10 and udp.port == 53* as the display filter. Competitors should notice that `10.1.1.10` is sending DNS packets to `10.5.5.5` (which is expected as `10.5.5.5` has been the DNS server for all challenges). Competitors should also notice that `10.1.1.10` is sending a lot of DNS packets to `10.2.2.20`; however, these packets contain a lot of warnings about malformed packets, unknown errors, etc.
14. Right-click any DNS packet that has `10.1.1.10` as the source and `10.2.2.20` as the destination. Click **Follow** and **UDP Stream**. Viewing the data as ASCII, we see references to H.264/MPEG-4 and videolan. This does not appear to be DNS traffic!
15. Change the *Show data as* to **Raw**, click **Save As**, and save the file as *53.file*.
16. Open a terminal and browse to the file you just saved. Run the command below to discover the type of file it is. The file is an MP4 file. 

```bash
file 53.file
```
17. Run the command below to open the file.

```bash
open 53.file
```

If your data is corrupted, this is because UDP is a connection-less protocol and does not guarantee delivery. These streams are sent every couple of minutes. Find another UDP stream. 

18. Examine the video. Notice the tree in the dark. This differs from the other video streams seen over HTTP.
19. Run the command below to see if there is any additional data hidden within this file.

```bash
binwalk 53.file
```

20. We see a zip file is within the data and contains the file **a.mp4** within. Run the command below to unzip this file.

```bash
unzip 53.file
```

21. We now see a file named **a.mp4**. Open that file and notice some dots. This is part of the 8-digit secret code!

22. Repeat the steps above to extract the hidden mp4 file from UDP traffic 25, 67, 68, 69, and 123. Port 123 is the answer to Question 1. When complete, you can see each video placed in this orientation shows an 8-digit code in Braille. Decode the Braille and you have found how insiders are sending the launch code over the network! It might be easiest to take a screenshot of each video and use a local tool such as Paint to orient the pictures in this manner.

```
A B C
D E F
```
