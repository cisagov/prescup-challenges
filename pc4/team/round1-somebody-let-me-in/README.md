# Somebody Let Me In

Intercept, replay, and analyze key code transmission traffic and services in order to regain access to a locked part of the ship.

**NICE Work Roles**
 - [Exploitation Analyst](https://niccs.cisa.gov/workforce-development/nice-framework)
 - [Vulnerability Assessment Analyst](https://niccs.cisa.gov/workforce-development/nice-framework)

**NICE Tasks**
 - [T0028](https://niccs.cisa.gov/workforce-development/nice-framework)- Conduct and/or support authorized penetration testing on enterprise network assets.
 - [T0591](https://niccs.cisa.gov/workforce-development/nice-framework) - Perform analysis for target infrastructure exploitation activities.
 - [T0608](https://niccs.cisa.gov/workforce-development/nice-framework) to identify potential avenues of access.
 - [T0641](https://niccs.cisa.gov/workforce-development/nice-framework) - Create comprehensive exploitation strategies that identify exploitable technical or operational vulnerabilities.

## Background

We have accidentally locked ourselves out of the nuclear fuel storage compartment. To add insult to injury, the last person to access the storage compartment accidentally left all three(3) key FOBs necessary to open the door inside the compartment along with the fuel. Fortunately, the FOBs were built with a hair trigger button and as the ship travels the FOBs are sending their respective signals to the door receivers as they bounce around the currently depressurized cabin. The primary receiver has been damaged, but a secondary receiver that accepts the FOB transmissions has been enabled, with varying success. You will have to intercept this FOB<->Receiver traffic to analyze and recover the necessary door codes and enter them manually. Once you have successfully entered all three(3) codes, the doors will open.

The three FOB/receiver networks are located in the 133.45.151.0/24, 133.45.152.0/24, and 133.45.153.0/24 spaces. Each receiver exists at the .250 address of its respective network. The addresses in the .251-.254 range of each respective network are available for your use.

You will need to determine the exact IP/MAC address pairs of the FOBs in order to spoof, intercept, and potentially modify the traffic in transit to submit or deduce the codes. 

```
You may not see traffic for the first 5 minutes after deployment. This is normal. This delay provides teams the time to situate themselves on the network before traffic begins.
```

## Getting started

Please follow the instructions in the [challenge directory](./challenge) to setup before starting this challenge offline.

## Main Objectives:

- Discover the three(3) key FOB IP/MAC address pairs
- Discover the three(3) door receiver MAC addresses
- Intercept and analyze/replay/alter key transmission traffic as outlined by the requirements below by ARP spoofing (you must do this to "sniff" the traffic)
- FOB #1: A simple replay/reuse attack will work
- FOB #2: The FOB uses a sequence of codes  
- FOB #3: The FOB is not working properly and you will need to solve this one on your own. The key increments by some value on each attempt, but we can't find the manual to figure out how, but the key you use is part of the function.
    
Useful tools include (but you may use what you wish):
- arping (requires sudo)
- asrpoof
- dsniff
- nmap
- Wireshark/tcpdump

## Hints

- You must configure Tully/Kali with a valid address on eth0 when attempting to connect to the receivers
- If spoofing causes traffic to no longer be received by your local Tully/Kali, try rebooting Tully/Kali as this usually solves the issue, or attempt to simply restart networking

## Challenge Questions

1. What is the hex code for unlocking the first door mechanism?
2. What is the hex code for unlocking the second door mechanism?
3. What is the hex code for unlocking the third door mechanism?
