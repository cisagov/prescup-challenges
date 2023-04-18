# Sharkbyte! Ooh ha ha!

Analyze Spaceship network traffic.

**NICE Work Roles**
- [Data Analyst](https://niccs.cisa.gov/workforce-development/nice-framework/work-roles/data-analyst)

**NICE Tasks**
- [T0366](https://niccs.cisa.gov/workforce-development/nice-framework/tasks/t0366) - Develop strategic insights from large data sets.
- [T0342](https://niccs.cisa.gov/workforce-development/nice-framework/tasks/t0342) - Analyze data sources to provide actionable recommendations.

## Background

There are two different subnets on the _Dauntless Spaceship_ that have network traffic on them -- the Engine subnet and the Sensor subnet.

The traffic within the Engine subnet is not understood by anybody on board. Documentation is limited. You must identify how the Spaceship Engine Monitoring System (SEMS) works so we can understand if it becomes compromised in the future (or even now!)

The Sensor subnet may have been compromised. You must answer the questions to identify if an IP address is sending out spoofed/illegitimate sensor status updates to the server on the Dauntless Sensor System (DSS).

## Getting Started

The Engine subnet traffic is available as an ISO on the provided Kali workstation. Questions **Engine Q[1-6]** are related to this pcap. Some guidance regarding the custom SEMS protocol is found within the ISO. **ONLY USE THE DEFAULT WIRESHARK CONFIGURATION PROFILE (as user or root). UNAPPLICABLE PROTOCOLS HAVE BEEN DISABLED ON THIS PROFILE. ALL UDP/6186 TRAFFIC IS ASSOCIATED WITH SEMS.**

The Sensor subnet traffic is only available on the Ubuntu Server (via ISO) due to network segmentation. You must run the command `sudo mount /dev/cdrom /media` to be able to view the pcap in the `/media` directory. You may want to copy this pcap to your home directory for analysis. Questions **Sensor Q[1-4]** are related to this pcap. Tools such as tshark, tcpdump, and suricata are available for you on the Ubuntu Server.

- The DSS sensors send updates to the DSS server at 172.31.57.5.
- The DSS server replies with the same data payload back to the DSS sensor verifying receipt

The Kali and Ubuntu Server VMs are located on different subnets of the spaceship and cannot communicate with each other. The Kali and Ubuntu Server VMs are unable to sniff their subnets live. We only have these pcaps for analysis.

__To play this challenge offline, the files from the ISO are available in the [challenge directory](./challenge)__

## Challenge Questions

1. Engine Q1: How many packets are associated with Engine 1?
2. Engine Q2: When all five flags are turned on, the status code should be Fatal; however, one packet with all flags turned on did not respond with a Fatal Status. What is the packet number of this packet?
3. Engine Q3: What is the lowest the burn speed can be without the Gas Flag being turned on?
4. Engine Q4: The Oil Flag is turned on when Burn Speed is at least ANSWER1 (or over) and Temperature reaches ANSWER2 (or below)? Submit your answer as ANSWER1:ANSWER2 (e.g., 55:1234)
5. Engine Q5: What is the highest recorded temperature of any engine? (it may have hit this level once, or more than once; however, NEVER higher).
6. Engine Q6: The Other Flag appears to be very buggy. How many times has the Other Flag been triggered, regardless of potentially other flags being turned on/off as well.
7. Sensor Q1: What is the 3-digit identifier for Paul?
8. Sensor Q2: A codename is being spoofed as the 24-hr key is incorrect. What was the packet number of the spoofed packet sent to the DSS Server?
9. Sensor Q3: What is the codename being spoofed?
10. Sensor Q4: What was the incorrect 24-hr key being used for the spoofed codename?
