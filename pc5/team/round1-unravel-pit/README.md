# Unravel Pit

Important sensitive data was stolen from the network of the Aurellian commercial spaceship, *Daunted*. Using the provided security tools and Security Onion data, investigate *Daunted*'s network and uncover the details of the data breach.

**NICE Work Roles**

- [Cyber Defense Analyst](https://niccs.cisa.gov/workforce-development/nice-framework/)
- [Network Operations Specialist](https://niccs.cisa.gov/workforce-development/nice-framework/)

**NICE Tasks**

- [T0023](https://niccs.cisa.gov/workforce-development/nice-framework/): Characterize and analyze network traffic to identify anomalous activity and potential threats to network resources.
- [T0259](https://niccs.cisa.gov/workforce-development/nice-framework/): Use cyber defense tools for continual monitoring and analysis of system activity to identify malicious activity.
- [T0291](https://niccs.cisa.gov/workforce-development/nice-framework/): Examine network topologies to understand data flows through the network.

## IMPORTANT
This challenge is only partially open sourced. The files in the [challenge directory](./challenge) are provided to give a starting point if you want to recreate the challenge on your own. The full challenge can be completed on the hosted site.

## Background

Someone on the *Daunted*'s network stole important customer data related to the *Daunted*'s online shop.

The user machines are located on the `10.1.1.0/24` network. The shop is located on the network DMZ at `10.7.7.7`.

## Getting Started

On the Kali VM Desktop, navigate to `challenge.us/files` and download the provided .pcapng file. Use the packet capture and information from the Security Onion server at `10.4.4.4` to get started.

## Challenge Questions

1. What is the root password retrieved from the shop?
2. Which internal IP address was responsible for the attack?
3. What is the name of the file that was exfiltrated?
4. To which IP address and port was the file exfiltrated? Use the format address:port in the answer.
