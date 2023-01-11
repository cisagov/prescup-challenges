# Sharkbyte! Ooh ha ha!

_Solution Guide_

## Overview

This challenge consists of two separate parts. One part has the team analyzing engine status packets with a custom, but provided payload data structure. The team will need to construct various display filters using the information provided about the structure in order to solve the questions. The other part requires finding spoofed traffic within the sensor network.

## Engine Subnet

Log in to Kali and open the SEMS.txt found in the ISO. Read this to understand the SEMS packet structure and why we want to slice certain values from various positions within the data payload on the packets.

Below are examples of how to can search for a specific byte within the data field. This is all knowledge competitors should be able to correlate and apply themselves after readings the SEMS.txt file. The content of that file is reiterated here for easy reference:

All but the first two of the following values are ASCII-formatted:
- `data.data[0]` is the specific byte in the data that shows Status
- `data.data[1]` is the specific byte in the data that shows Engine
- `data.data[2-5]` are the specific byte in the data that shows Angle_Degree
- `data.data[6-7]` are the specific byte in the data that shows Burn_Speed
- `data.data[8-11]` are the specific byte in the data that shows Temperature
- `data.data[12-13]` would show the first flag, if turned on. Otherwise, if no flags are present, data.data[12] should indicate 0a (as stated in SEMS.txt)
    - This flag could be Gas, Oil, Air, Balance, or Other (as stated in SEMS.txt)
- `data.data[14-15]` would show the second flag, if turned on.
    - This flag could be Oil, Air, Balance, or Other (as stated in SEMS.txt) (Gas, if turned on is always in the first flag)
- `data.data[16-17]` would show the third flag, if turned on.
    - This flag could be Air, Balance, or Other (as stated in SEMS.txt) (Gas, if turned on is always in the first flag. Oil, if turned on, would be in the first or second flag.)
- `data.data[18-19]` would show the fourth flag, if turned on.
    - This flag could be Balance, or Other (as stated in SEMS.txt) (Gas, Oil, and Balance would be in the first three flags, if turned on.)
- `data.data[20-21]` would show the fifth flag, if turned on.
    - This flag could only be Other and this would indicate all flags are also turned on as well, since flag other was pushed to this placement.

Next, open the pcap found in the ISO in Wireshark and we can start answering the questions:

### Engine Q1

_How many packets are associated with Engine 1?_

```
udp.port == 6186 && data.data[1] == 31
```

`data.data[1]` is the byte in the packet payload that corresponds to a specific Engine and the value `31` indicates Engine 1. As indicated in the challenge guide, ALL UDP 6186 traffic is used for SEMS traffic and only SEMS traffic.

### Engine Q2: Variation 1

_When all five flags are turned on, the status code should be Fatal; however, one packet with all flags turned on did not respond with a Fatal Status. What is the packet number of this packet?_

```
udp.port == 6186 && data.len == 23
Find the packet that does not have 05 as the first value
```
When all five flags are turned on, the length of the payload is 23. The packet with this invalid status is number 37205.

### Engine Q2: Variation 2

_When four flags are set, the Status should be either Warning or Fatal. What is the packet number of the packet that failed to correctly set the Status?_

```
udp.port == 6186 && data.len == 21
Find the packet that does not have 04 or 05 as the first value in the data.
```

When four are turned on, the length of the payload is 21. The packet with an invalid status is number 23830.

### Engine Q2: Variation 3

_When all five flags are turned on, the status code should be Fatal. How many packets contain a Fatal status code with all five flags for Engine 1?_

```
udp.port == 6186 && data.len == 23 && data.data[1] == 31
Count the displayed packets
```

When all five flags are turned on, the length of the payload is 23. We also want to specify Engine 1 in the filter (the same way as question 1).

### Engine Q2: Variation 4

_When at least four flags are turned on, the status code should be Fatal; however, how many packets with at least four flags did not return a Fatal status code?_

```
udp.port == 6186 && (data.len == 21 or data.len == 23) && data.data[0] != 05
Count the displayed packets
```

When four or five flags are turned on, the length of the payload is 21 or 23, respectively. Then we just search for packets where the status byte is not 05 (Fatal).

### Engine Q3

_What is the lowest the burn speed can be without the Gas Flag being turned on?_

```
udp.port == 6186 && data.data[12-13] == 30:31 && data.data[6-7] == 31:39
Verify burn speed of 19 has the Gas Flag turned on as a sanity check.

udp.port == 6186 && data.data[12-13] != 30:31 && data.data[6-7] == <VALUE1>:<VALUE2>
Inverting the gas flag check above, we can then increment the burn speed value until packets show up again.
```

As noted in the Wireshark documentation [6.4.2.2](https://www.wireshark.org/docs/wsug_html_chunked/ChWorkBuildDisplayFilterSection.html#_comparing_values), the above use of 30:31 and other colon-separated values indicates a byte sequence to filter on. We're looking for ASCII-formatted fields, so each digit is a whole byte and is in the 0x30 to 0x39 range.

In the first search, you're looking for the Gas Flag (01) (represented by 30:31) in the [12-13] position. In the [6-7] position is the Burn Speed. The value of 19 for the burn speed is a guessed value. If no results show up, try another value. Finding results here just indicates that our search is not far off, and this part is optional.

Once we find packets, we can invert the check for the gas flag to only find results where it is off (per the instructions, the gas flag must always be in the first flag position). The most likely case will return no results when the check is flipped - so we should increment the burn speed value until we get packets. The first value that displays results is what we're looking for.

### Engine Q4: Variation 1

_The Oil Flag is turned on when Burn Speed is at least ANSWER1 (or over) and Temperature reaches ANSWER2 (or below)? Submit your answer as ANSWER1:ANSWER2 (e.g., 55:1234)_

```
Searching through the packet values will eventually lead you to these 2 searches.
udp.port == 6186 && (data.data[12-13] == 30:32 or data.data[14-15] == 30:32) && data.data[6-7] == 38:30
udp.port == 6186 && (data.data[12-13] == 30:32 or data.data[14-15] == 30:32) && data.data[8-11] == 31:39:39:39
```

We know the Oil Flag (02, indicated by 30:32), if turned on, is either in the [12-13] or [14-15] position. We are looking for when the Oil Flag is on, what Burn Speed [6-7] is being reached. You could search for `udp.port == 6186 && (data.data[12-13] == 30:32 or data.data[14-15] == 30:32) && data.data[6-7] == 37:30` and prove that Burn Speed 70 is not high enough to turn the Oil Flag on. Adjust data.data[6-7] == TWO:BYTES until you reach a Burn Speed number (80, indicated by 38:30) that turns the Oil Flag on.

Next we want to know the highest Temperature [8-11] reached. You could search for `data.data[12-13] == 30:32 or data.data[14-15] == 30:32) and data.data[8-11] == 31:38:30:30` and prove that Temperature 1800 is low enough to turn the Oil Flag on. Adjust data.data[8-9] == TWO:BYTES until you reach a Temperature where the first two Temperature digits (20, indicated by 32:30) does not turn the Oil Flag on. Then you can fine tune your search and look for the complete Temperature value [8-11] and find that `udp.port == 6186 && (data.data[12-13] == 30:32 or data.data[14-15] == 30:32) and data.data[8-11] == 31:39:39:39` (1999, as indcated by 31:39:39:39) turns the Oil Flag on, but `udp.port == 6186 && (data.data[12-13] == 30:32 or data.data[14-15] == 30:32) and data.data[8-11] == 32:30:30:30` (2000, as indicated by 32:30:30:30) does not.

### Engine Q4: Variation 2

_The Oil Flag is turned on when Burn Speed is at least ANSWER1 (or over) and Temperature reaches ANSWER2 (or below)? Submit your answer as ANSWER1:ANSWER2 (e.g., 55:1234)_

```
Searching through the packet values will eventually lead you to these 2 searches.
udp.port == 6186 && (data.data[12-13] == 30:32 or data.data[14-15] == 30:32) && data.data[6-7] == 37:35
udp.port == 6186 && (data.data[12-13] == 30:32 or data.data[14-15] == 30:32) && data.data[8-11] == 31:38:39:39
```

We know the Oil Flag (02, indicated by 30:32), if turned on, is either in the [12-13] or [14-15] position. We are looking for when the Oil Flag is on, what Burn Speed [6-7] is being reached. You could search for `udp.port == 6186 && (data.data[12-13] == 30:32 or data.data[14-15] == 30:32) && data.data[6-7] == 37:30` and prove that Burn Speed 70 is not high enough to turn the Oil Flag on. Adjust data.data[6-7] == TWO:BYTES until you reach a Burn Speed number (75, indicated by 37:35) that turns the Oil Flag on.

Next we want to know the highest Temperature [8-11] reached. You could search for `data.data[12-13] == 30:32 or data.data[14-15] == 30:32) and data.data[8-11] == 31:38:30:30` and prove that Temperature 1800 is low enough to turn the Oil Flag on. Adjust data.data[8-9] == TWO:BYTES until you reach a Temperature where the first two Temperature digits (19, indicated by 31:39) does not turn the Oil Flag on. Then you can fine tune your search and look for the complete Temperature value [8-11] and find that `udp.port == 6186 && (data.data[12-13] == 30:32 or data.data[14-15] == 30:32) and data.data[8-11] == 31:38:39:39` (1899, as indcated by 31:38:39:39) turns the Oil Flag on, but `udp.port == 6186 && (data.data[12-13] == 30:32 or data.data[14-15] == 30:32) and data.data[8-11] == 31:39:30:30` (1900, as indicated by 31:39:30:30) does not.

### Engine Q4: Variation 3

_The Oil Flag is turned on when Burn Speed is at least ANSWER1 (or over) and Temperature reaches ANSWER2 (or below)? Submit your answer as ANSWER1:ANSWER2 (e.g., 55:1234)_

```
Searching through the packet values will eventually lead you to these 2 searches.
udp.port == 6186 && (data.data[12-13] == 30:32 or data.data[14-15] == 30:32) && data.data[6-7] == 37:38
udp.port == 6186 && (data.data[12-13] == 30:32 or data.data[14-15] == 30:32) && data.data[8-11] == 32:30:39:39
```

We know the Oil Flag (02, indicated by 30:32), if turned on, is either in the [12-13] or [14-15] position. We are looking for when the Oil Flag is on, what Burn Speed [6-7] is being reached. You could search for `udp.port == 6186 && (data.data[12-13] == 30:32 or data.data[14-15] == 30:32) && data.data[6-7] == 37:30` and prove that Burn Speed 70 is not high enough to turn the Oil Flag on. Adjust data.data[6-7] == TWO:BYTES until you reach a Burn Speed number (78, indicated by 37:38) that turns the Oil Flag on.

Next we want to know the highest Temperature [8-11] reached. You could search for `data.data[12-13] == 30:32 or data.data[14-15] == 30:32) and data.data[8-11] == 31:38:30:30` and prove that Temperature 1800 is low enough to turn the Oil Flag on. Adjust data.data[8-9] == TWO:BYTES until you reach a Temperature where the first two Temperature digits (21, indicated by 32:31) does not turn the Oil Flag on. Then you can fine tune your search and look for the complete Temperature value [8-11] and find that `udp.port == 6186 && (data.data[12-13] == 30:32 or data.data[14-15] == 30:32) and data.data[8-11] == 32:30:39:39` (2099, as indcated by 32:30:39:39) turns the Oil Flag on, but `udp.port == 6186 && (data.data[12-13] == 30:32 or data.data[14-15] == 30:32) and data.data[8-11] == 32:31:30:30` (2100, as indicated by 32:31:30:30) does not.

### Engine Q4: Variation 4

_Multiple criteria must meet for the oil flag to turn on. What is the LOWEST burn speed (ANSWER1) recorded when the oil flag was on?  What is the HIGHEST temperature (ANSWER2) recorded when the oil flag was on? Submit your answer as ANSWER1:ANSWER2 (e.g., 12:1234)_

```
Searching through the packet values will eventually lead you to these 2 searches.
udp.port == 6186 && (data.data[12-13] == 30:32 or data.data[14-15] == 30:32) && data.data[6-7] == 37:39
udp.port == 6186 && (data.data[12-13] == 30:32 or data.data[14-15] == 30:32) && data.data[8-11] == 31:33:33:37
```

We know the Oil Flag (02, indicated by 30:32), if turned on, is either in the [12-13] or [14-15] position. We are looking for when the Oil Flag is on, what Burn Speed [6-7] is being reached. You could search for `udp.port == 6186 && (data.data[12-13] == 30:32 or data.data[14-15] == 30:32) && data.data[6-7] == 37:30` and prove that Burn Speed 70 is not high enough to turn the Oil Flag on. Adjust data.data[6-7] == TWO:BYTES until you reach a Burn Speed number (79, indicated by 37:39) that turns the Oil Flag on.

Next we want to know the highest Temperature [8-11] reached. You could search for `data.data[12-13] == 30:32 or data.data[14-15] == 30:32) and data.data[8-11] == 31:34:30:30` and prove that Temperature 1400 is low enough to turn the Oil Flag on. Adjust data.data[8-9] == TWO:BYTES until you reach a Temperature where the first two Temperature digits (12, indicated by 31:32) does not turn the Oil Flag on. Then you can fine tune your search and look for the complete Temperature value [8-11] and find that `udp.port == 6186 && (data.data[12-13] == 30:32 or data.data[14-15] == 30:32) and data.data[8-11] == 31:33:33:37` (1337, as indcated by 31:33:33:37) turns the Oil Flag on, but `udp.port == 6186 && (data.data[12-13] == 30:32 or data.data[14-15] == 30:32) and data.data[8-9] == 31:34` (14XX, as indicated by 31:34) does not.

### Engine Q5

_What is the highest recorded temperature of any engine? (it may have hit this level once, or more than once; however, NEVER higher)_

```
tshark -r spaceship.pcapng -T fields -e data.data | cut -c 17-24 | sort -n
Convert highest ASCII value to decimal (e.g., 33 35 38 37 is 3587, or 34 30 30 30 is 4000)
```

Using tshark is a helpful way to search to carve out specific values. In this command, we are cutting the 17th - 24th characters and sorting them highest to lowest. The highest is the answer.

### Engine Q6

_The Other Flag appears to be very buggy. How many times has the Other Flag been triggered, regardless of potentially other flags being turned on as well?_

```
udp.port == 6186 and (data[12-14] == 30:35:0a or data[14-16] == 30:35:0a or data[16-18] == 30:35:0a or data[18-20] == 30:35:0a or data[20-22] == 30:35:0a)
Value is the number of displayed packets (found at bottom of Wireshark)
```

We know that the length of each data.data is different based on how many flags is turned on. To avoid confusion, we will also search for the 0a byte which indicates the end of the packet (0a does not appear anywhere else in these packets). We do not know if the Other Flag (30:35) is in the [12-13], [14-15], [16-17], [18-119], or [20-21] positions, show ensuring the 0a follows these values in each position is critical.

## Sensor Subnet

Log in to the Ubuntu Server and mount the ISO with

```
sudo mount /dev/cdrom /media
```

and then copy the mounted pcap from /media to home directory with

```
cp /media/dauntless-sensors.pcapng .
```

### Sensor Q1

_Find 3-digit identifier for <NAME>. (The UUID value)_

```
tcpdump -Ar dauntless-sensors.pcapng | grep -A3 -B3 -i <NAME>
```

All of the used flags can be found with `man tcpdump` and `man grep`. To summarize, we're reading the pcap file and printing out packets as ASCII with `tcpdump -Ar`, and then using `grep -A3 -B3 -i <NAME>` to show extra context before and after the supplied name.

### Sensor Q2

_A codename is being spoofed as the 24-hr key is incorrect. What was the frame number of the spoofed packet sent to the DSS Server?_

```
tshark -r dauntless-sensors.pcapng -T fields -e ip.src -e frame.number -e data | grep `echo -n "DAILYKEY:" | xxd -p`

Run the above first and then add the following inverse filter:

tshark -r dauntless-sensors.pcapng -T fields -e ip.src -e frame.number -e data | grep `echo -n "DAILYKEY:" | xxd -p` | grep -v `echo -n "DAILYKEY: A7554" | xxd -p`
```

We're first searching for packets that include the ASCII string "DAILYKEY:" to find all packets including the 24-hour key. In the output, the vast majority of results contain the same key, which starts with A7554 - so filter out all packets that contain the real key and we see there is another key in the output.

### Sensor Q3

_What is the codename being spoofed?_

```
tshark -x -r dauntless-sensors.pcapng -Y frame.number==<FRAMENUMBERPREVIOUSLYFOUND>
```

Using the frame number from the previous question, we get the information needed to solve this question and the next.

### Sensor Q4

_What was the incorrect 24-hr key being used for the spoofed codename?_

```
tshark -x -r dauntless-sensors.pcapng -Y frame.number==<FRAMENUMBERPREVIOUSLYFOUND>
```
