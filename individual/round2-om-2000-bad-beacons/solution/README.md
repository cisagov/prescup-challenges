<img src="../../../logo.png" height="250px">

# Bad Beacons

## Solution


To solve the Bad Beacons problem, we first need to identify what "beaconing" behavior is.  
Beaconing behavior can be a host that is making regular periodic connections to another host. For example, a beaconing host might make a network connection every 5 minutes. In the real world, these periodic connections may also have some jitter value. For example, the regular rate might be 5 min plus/minus 2 min for jitter, which means connections will occur between every 3 and 7 minutes.  

In this problem, we must isolate a host that is exhibiting beaconing traffic behavior from a PCAP file. One way to do this is to write a script that will parse the PCAP file into a format that can be queried, then perform some queries to find the beaconing behavior. The example solution script can be created by running the `download-challenge-script-linux.sh` if you are on Linux or `download-challenge-script-mac.sh` if you are on Mac. On Windows, you
will either need a Linux VM or install the Linux subsystem (or some solution for running bash scripts and common Unix utilities).
Both scripts will produce the example solution script named `example_solution.py`.

The example solution code uses Python and the [Pandas](https://pandas.pydata.org/) data analysis library to perform the queries. Pandas has an excellent method for reading CSV files into SQL-Like tables that are easy to query. 

There is some code in the example script that converts the PCAP file into a CSV file. It makes use of the [tshark](https://www.wireshark.org/docs/man-pages/tshark.html) command to process the PCAP and another custom function to transform the tshark output into a CSV. 

Once the CSV is created, Pandas reads the data into a table-like data structure called a DataFrame. It is possible to form groups of rows in the DataFrame by using the groupBy() function. Useful groups here would be Source/Destination IP Address Pairs. Grouping on these two fields will form many groups of packets that have the same Source/Destination IP Address. It might also help to limit the search space to only packets which match the Source IP Address given in the challenge. 

Because the challenge is asking for periodic connections, finding the time difference between each packet will be useful. We can then narrow the search space by filtering out packets that happen to have less/more than a certain amount of time between them. This step may take some tuning, but the example solution filters out packets that are equal to or more than 60 seconds apart from the previous packet with the same Source/Destination IP Address. 

The example solution then prints out the time since the last packet for all packets remaining in the groups. These are organized by Source/Destination IP Address Pairs. With some manual inspection, the answer should appear to be quite evident because the time differences between the packets in the group are very regular (packets should have the same difference printed plus or minus about 1 second). The flag is then the Destination IP Address in that group. 

To execute the example script on a Windows machine, you'll need `Python 3` installed and environment variables defined so that `python` and `pip` commands are recognized at the command prompt. You'll also need `Wireshark` installed and environment variable defined so that the `tshark` program is recognized at the command prompt. Apart from that, you'll also need the following Python modules - `python-dateutil`, `numpy`, `pandas`. You may use `pip install <module-name>` to install these modules.

Use the following command to execute the script - 

```
python example_solution.py --pcap challenge.pcap > output.txt
```

Review the output file and find the source/destination IP address pairs for which the data packets are sent at a fairly regular time interval. Here is the snippet from the `output.txt` file that also contains the flag value.

<img src="screenshot/Picture1.png">

The output is grouped by source/destination IP addresses, and it displays the packet number and the time difference between each consecutive packets. We can see the source IP address (`192.168.106.152`) is that of the compromised workstation, and each successive packet is sent every 61 +/- 1 sec. The flag for this challenge is the destination IP address in this group.

Flag - `192.168.106.10`

## License
Copyright 2020 Carnegie Mellon University. See the [LICENSE.md](../../../LICENSE.md) file for details.