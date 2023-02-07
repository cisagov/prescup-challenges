# Reporting In Solution

1. Open Wireshark and begin capturing packets on the Ethernet0 interface.
2. Drag the prescup3-reportingin.exe file from the DVD drive to the desktop.
3. Open PowerShell or Command Prompt, change directory to C:\Users\User\Desktop if it isn't there already.
4. Run `./prescup3-reportingin.exe hello` in the shell window and wait for the report to be accepted.
5. Now examine the traffic in Wireshark. The local machine is in the subnet 202.128.10.0/24, with an address in the range 10 to 50 (DHCP). 202.128.10.5 is the grading server, which may show up in the captured traffic.
6. (Clue) There are two non-LAN addresses that should show up in the traffic. One is 104.27.195.88, and the other is 58.174.47.117. Inspecting the HTTP traffic shows that both are unencrypted exchanges. The former HTTP request returns HTML that includes your IP address. The latter seems to be JSON that includes your report, including the "hello" text you entered on the command line.
7. 58.174.47.117 is one of the reporting addresses.
8. The fact that the executable is doing an IP address lookup is a major clue to its behavior. We can experiment with its behavior by hijacking the GET request.
9. A python script for solving this challenge is provided in the file [solution_script.py](./solution_script.py). Place this file on the Desktop of your VM. 
10. In an Administrator command prompt, run the following command: `netsh int ip sh int` and confirm that the Loopback Pseudo-Interface has an index of 1 (first column).
11. Then run `netsh int ip add addr 1 104.27.195.88/32 st=ac sk=tr` to redirect any traffic to the IP server to your local machine instead.
12. You can close the admin prompt now, and open another, non-elevated shell on your desktop and run `python .\script.py`.
13. Now run the reporting application again and examine the captured traffic. It should be apparent that the server you just created is what actually responded.
14. (Clue) You can try experimenting with the IP address being returned. Depending on your choice of addresses, the reporting program will give an error message or attempt to reach to a reporting server. You may stumble onto a different reporting server by this approach, but it's not recommended.
15. (Clue) Instead, we're going to do some basic analysis on the binary file. In one of your command prompts (existing or make a new one), in the `C:\Users\User\Desktop` folder, run `Strings64.exe prescup3-reportingin.exe > strings.txt`.
16. (Clue) From the string dump, you can find some very helpful information. After scrolling past some of the junk data in the file, you will start to see references indicating that this program was written in the Rust language. There is also a string indicating that the `csv` crate is being used in this program. That's a good indication that this program is reading a csv file at some point. But where is it?
17. (Clue) If you continue through the dump, you will eventually come across the csv file being used. Well, actually there are three if you look closely. One is associating IPv4 networks with geoname IDs, the second one associates IPv6 networks with geoname IDs, and the third one associates geoname IDs with various data about countries. From this we can make a few hypotheses about how to find the reporting servers, but for the purposes of this solution guide, we'll skip straight to the correct one.
18. Each reporting server is located on a different continent, so you need to find an IP address that will trick the reporting app into believing that it's being used on a different continent. If you look through the data and find the associated continent, you will be able to tell that it's in OC (Oceania). The grading server only has six boxes, suggesting that there is not likely to be an Antarctic server. From here you can reverse search one IP address per continent, and update your spoof server for each one to get a valid address on each of the six populated continents.
19. The six reporting servers are as follows:
    - 1.235.189.106
    - 58.172.47.117
    - 45.104.34.74
    - 128.237.119.12
    - 152.200.19.77
    - 2.69.27.123
