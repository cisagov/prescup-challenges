# Xeno Cult Solution

_Solution Guide_ 

## Overview

The Aurelian security forces have been sending out probes to search for the hidden base of a cult of ancient alien worshippers; however, the cultists jam their probes as they travel, preventing them from reporting their location. The Aurelian security provides your team access to some files so the team can attempt to find the hidden base. Your team must discover coordinates to their location.

Coordinates consist of two (2) sets of three (3) case insensitive alphanumeric characters. (i.e., 123/abc, a2n/3ib)

In this directory you will find the [client](https://github.com/cisagov/prescup-challenges/blob/main/pc4/team/round3b-xeno-cult/solution/flightclient.py) and [server](https://github.com/cisagov/prescup-challenges/blob/main/pc4/team/round3b-xeno-cult/solution/multiconn-server.py) python scripts used to generate this data. DO NOT SHARE WITH COMPETITORS. The flight(client).py was executed with `flight(client).py > internal_logs.txt` to show all locations of ships and probes (with jamming details). Again, these should not be shared with competitors. Click [here](https://github.com/cisagov/prescup-challenges/blob/main/pc4/team/round3b-xeno-cult/solution/internal_logs.txt) for the `internal_logs.txt` file.

## Question 1

Connect to SMB and download required files.

```bash
smbclient -N -L //10.10.10.140
smbclient //10.10.10.140/SecuritySearchLogs
ls
get pcaps.tar.gz
get probelocations.txt
exit
```

You should now have the two required files. Run `tar xf pcaps.tar.gz` to extract all PCAPs.

Find the location of the jammed transmissions.

1. Challengers should verify the pcap files are now accessible in their current directory with the command `ls`. Open comm.pcap10 with Wireshark.

2. Challengers notice the client sends payload containing syntax such as `probe_10919 A42 51F s`. This indicates the probe, X-axis, Y-axis, and direction (n, ne, e, se, s, sw, w, nw).

    Challengers notice the server echos the payload back to the server after reception.

3. Challengers must find the packets that are missing to identify when the probe was being jammed. There are several ways to solve this. One way is to extract all data payload from client across all PCAPs, normalize the data (if needed), and compare the data to the known locations (and timestamps) of the probes.

4. Challengers may want to only carve through packets sent from client (and ignore the server echos).

    ```bash
    for i in comm.pcap*; do tcpdump -r $i src 198.51.100.57 -w client-$i; done
    ```

5. Challengers may want to extract only the payload data from each client-only packet and save it as ASCII to a text file. This may take a few minutes.

    ```bash
    for i in client-*; do tshark -r $i -T fields -e data | xxd -r -p >> pcap.txt; done
    ```

6. Save a backup.

    ```bash
    cp pcap.txt pcap.txt.bak`
    ```

7. Add new line before each probe to interpret the data similar to probelocations.txt.

    ```bash
    sed -i 's/probe/\nprobe/g' pcap.txt
    ```

8. Sort pcap.txt.

    ```bash
    sort pcap.txt > sorted-pcap.txt
    ```

9. Remove the epoch time and sort `probelocations.txt` and save as sorted-probes.txt.

    ```bash
    cut -d ":" -f2 probelocations.txt | sort > sorted-probes.txt
    ```

10. Identify the number of times each probe was seen in the pcap and how many times it should have been seen based on the sorted-probes.txt.

    ```bash
    for i in {1..20000}; do echo -n "probe_"$i":" >> probes-results.txt && grep "probe_"$i" " sorted-probes.txt | wc -l >> probes-results.txt; done
    ```

    and while the previous command is running, open another terminal and run the command

    ```bash
    for i in {1..20000}; do echo -n "probe_"$i":" >> pcap-results.txt && grep "probe_"$i" " sorted-pcap.txt | wc -l >> pcap-results.txt; done
    ```

11. Find the difference between the files to see what pcap requests were jammed.

    ```bash
    diff probes-results.txt pcap-results.txt | less
    ```

12. We see probe_11 was seen 117 times (instead of 118), probe_134 was seen 117 times (instead of 118), probe_267 was seen 48 times (instead of 49), and many more.

13. Using probe_11 as an example, grep the probe number (notice the trailing space), view with less and scroll down until you see a line missing (e.g., the X and/or Y coordinates should always be different by 1 or remain). Notice that line containing C48 9E3 is missing. This is a location of jamming!

    ```bash
    grep "probe_11 " sorted-pcap.txt | less
    ```

14. Do the same thing with probe_134 and probe_267. You will find probe_134 is missing 04B B66 and probe_267 is missing FD1 343.

    ```bash
    grep "probe_134 " sorted-pcap.txt | less grep "probe_267 " sorted-pcap.txt | less
    ```

15. Run the command below to have a list of all probe numbers that had at least one jammed signal.

    ```bash
    diff probes-results.txt pcap-results.txt | grep c | cut -d "c" -f1 > jammed-probes.txt
    ```

16. We can create a bash script to automate the previous searches to only show differences between probes-results and pcap-results that have a missing line. Create a bash script titled diff-checker.sh and enter the code below.

    ```bash
    while read i; do
        grep "probe_"$i" " sorted-pcap.txt > pcap-$i.txt
        grep "probe_"$i" " sorted-probes.txt > probes-$i.txt
        diff pcap-$i.txt probes-$i.txt >> differences.txt
    done <jammed-probes.txt
    ```

17. Run the diff-checker.sh with the command:

    ```bash
    bash diff-checker.sh
    ```

18. To identify the X-coordinate of the base, we will see what X-coordinate was most popular (due to if a ship was simply going north or south, this x-coordinate would remain the same). Run the command below to identify that DBF appeared more than twice as much as any other x-coordinate as it appeared 7 times as a jammed signal!

    ```bash 
    cat differences.txt | grep '>' | cut -d " " -f3 | sort | uniq -c | sort -n
    ```

19. To identify the Y-coordinate of the base, we will see what Y-coordinate was most popular (due to if a ship was simply going east or west, this x-coordinate would remain the same). Run the command below to identify that 8B7 appeared three times as much as any other x-coordinate as it appeared 10 times as a jammed signal.

    ```bash
    cat differences.txt | grep '>' | cut -d " " -f4 | sort | uniq -c | sort -n
    ```

20. We have identified that the Base is located at DBF:8B7 (X:Y). Manually enter the coordinates at the Navigation System Workstation and launch *Dauntless*.
21. Enter Exploration Mode and make contact to gain access to the Seelax files.
22. Connect to SMB and download the Codex.
    
    ```bash
    smbclient -N -L //10.10.10.143
    smbclient //10.10.10.143/SeelaxEnlightenment
    ls
    get codexd
    exit
    ```

23. Transfer the downloaded codexd file to the Decrypter Workstation.