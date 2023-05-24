# Night of the Living Raspberries

Raspberry Pi devices are popular with certain Aurellians who collect and trade them. We were recently approached by an Aurellians Pi collector who was alarmed by the presence of malware on his Raspberry Pi system. Reverse engineer the malware and pinpoint the Indicators of Compromise (IOC).

**NICE Work Role**
[Cyber Defense Forensics Analyst](https://niccs.cisa.gov/workforce-development/nice-framework)

 **NICE Tasks**
- [T0182](https://niccs.cisa.gov/workforce-development/nice-framework) - Perform tier 1, 2, and 3 malware analysis.
- [T0288](https://niccs.cisa.gov/workforce-development/nice-framework) - Perform static malware analysis.
- [T0036](https://niccs.cisa.gov/workforce-development/nice-framework) - Confirm what is known about an intrusion and discover new information, if possible, after identifying intrusion via dynamic analysis.

## IMPORTANT

This challenge does not have any downloadable artifacts. You may complete this challenge in the hosted environment.

## Getting Started

You have been given access to the Raspberry Pi that was infected with the malware. You can connect using the following command `ssh pi@raspberry`, with the password `raspberry`. The malware will consist of two files: an executable and a file with an unknown format. 

Reverse engineer the Raspberry Pi malware to identify IOCs. Use any remote or local malware analysis techniques at your disposal in order to answer the questions. You may transfer the files to your Kali workstation using Secure Copy Protocol (SCP).

**Please note: the Pi computer might take a few seconds to run certain commands.**

## Challenge Questions

1. What is the full path of the named pipe that the malware makes?
2. What are the first 4 bytes of the key that the pi_helper binary uses to decode the pi-data? 
3. What port does the malware scan for?
4. What is the domain that the malware downloads itself from?
5. What 5 passwords does the malware try to log in with? Submit the passwords in a pipe-delimited ("|") list (order does not matter).
