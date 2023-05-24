# Is this on the test?

Given some internal traffic packet captures and a single penetration testing system, you must perform analysis to find a way to access a remote computer that is inside a company network.

**NICE Work Role:** 

- [Exploitation Analyst](https://niccs.cisa.gov/workforce-development/nice-framework)

**NICE Tasks:**
  - [T0028](https://niccs.cisa.gov/workforce-development/nice-framework) - Conduct and/or support authorized penetration testing on enterprise network assets.
  - [T0570](https://niccs.cisa.gov/workforce-development/nice-framework) - Apply and utilize authorized cyber capabilities to enable access to targeted networks.
  - [T0591](https://niccs.cisa.gov/workforce-development/nice-framework) - Perform analysis for target infrastructure exploitation activities.
  - [T0695](https://niccs.cisa.gov/workforce-development/nice-framework) - Examine intercept-related metadata and content with an understanding of targeting significance.

## IMPORTANT
This challenge is only partially open sourced. The files in the [challenge directory](challenge) are provided to give a starting point if you want to recreate the challenge on your own. The full challenge can be completed on the hosted site.

## Background

The company, Techstory, was created one year ago and provides online photo storage, as well as a virtual photo book that can be shared with other users. You have been contracted as a penetration tester to evaluate their current environment and attempt to infiltrate their network.

Techstory agreed to provide you with four packet capture files, each showing IP addresses within four different subnet blocks. These blocks are:
* `192.168.58.[40-50]`
* `192.168.132.[70-80]`
* `192.168.176.[110-120]`
* `192.168.210.[160-170]`

Be advised, the packet captures are old and may not accurately portray the current network configuration. You should gather other information about the network and its systems to aid in your analysis. The company will be operating normally with a majority of workers unaware that penetration testing is taking place.

## Getting started 

You have access to a Kali Linux system with no network configuration applied. On its desktop will be a folder named `subnets` which contains the packet captures. You must determine any valid and unused IP addresses to assign to your Kali system. Afterwards, perform reconnaissance and gain access to a vulnerable machine on the network to view the flag.

## Submission Format
When entering your submissions, please enter them in the following format:
1. Correct IP address configuration of Kali machine
2. Host name of vulnerable machine 
3. Port accessed (number, not name) 
4. Flag string found on the vulnerable machine
