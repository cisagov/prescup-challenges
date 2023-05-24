# Velociraptors are Not That Scary

Use a remote system management tool to investigate a cyber incident. 

**NICE Work Roles** 
- [Cyber Defense Forensics Analyst](https://niccs.cisa.gov/workforce-development/nice-framework)

**NICE Tasks**
- [T0175](https://niccs.cisa.gov/workforce-development/nice-framework).
- [T0432](https://niccs.cisa.gov/workforce-development/nice-framework) and use discovered data to enable mitigation of potential cyber defense incidents within the enterprise.

## IMPORTANT
This challenge does not have any downloadable artifacts. You may complete this challenge in the hosted environment.

## Background

There are reports of a cyber attack in a facility on planet Alpha in galaxy Sierra. You have been provided remote access to a system from that facility that needs to be investigated. The remote access is available through the **Velociraptor** tool.

## Getting Started

Analyze the system under investigation and answer the questions.

**Things to keep in mind:**

1. The Velociraptor client is installed on the system under investigation and is reporting to the Velociraptor server.
2. The Velociraptor web console (`https://192.168.1.100:8889`) is accessible from the `analyst` VM. 
3. Only *one* client system is showing up in the Velociraptor web console and that is the system that needs to be analyzed.

## Challenge Questions

1. There is suspicious UDP traffic originating from the system under investigation and destined to port 4444. What is the destination IP for those UDP packets?
2. Provide the name of the file being exfiltrated in those UDP packets.
3. Provide the name of the executable that is causing data exfiltration.
4. Another copy of the same executable (different filename) is also present on the system. Provide the name of the executable. 
5. The executable identified in the previous question was renamed on the system. Provide the previous filename of the executable.
