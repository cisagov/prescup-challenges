<img src="../../../pc1-logo.png" height="250px">

# Fire'd Up

## Solution

First, filter out all ftp, ftp-data, and ssh traffic to eliminate the local to local file transfers.
Next, it is easiest to view the Conversations statistics in Wireshark to see who are the remaining "top talkers" on the network. The Resolved Addresses stats are also useful for coordination between IP's and hostnames. After making a list of the remaining "top talkers" there should only be a handful left in each file.

One IP per pcap file is always watching Netflix. The IP for this can be seen in the resolved addresses list, so the IP watching Netflix can be eliminated.

Other IP's may be seen receiving large amounts of data from IP's that correspond to googlevideo or just Google. This traffic can be assumed to be YouTube traffic and most will also have packets that display "streamingvideoservice" in the requests.

If any top talkers remain, this may be due to the IP downloading files from the Internet (Skype, Wireshark, OpenEmu, and/or Nmap). These requests will display the website URLs directly, so it is rather simple to eliminate these as well.

If the file has an IP left that is using over 10M of bandwidth it will have to be the one user using FedVTE. Once this IP is found, you can see that the conversation takes place with 216.230.115.88 which resolves to fedvte.usalearning.gov in the Wireshark statistics. Since, online training sites approved by the gov't are authorized, this user is not breaking the rules, and therefore the only high bandwidth user with a valid excuse.

## Answer

Found in pcap1.pcapng: `10.9.8.147`

## License
Copyright 2020 Carnegie Mellon University.  
Released under a MIT (SEI)-style license, please see LICENSE.md in the project root or contact permission@sei.cmu.edu for full terms.
