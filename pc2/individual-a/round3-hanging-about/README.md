# Hanging About

Locate a hidden machine planted on the network by a malicious insider.

**NICE Work Roles:**

- [Cyber Defense Infrastructure Support Specialist](https://niccs.cisa.gov/workforce-development/nice-framework)

**NICE Tasks:**

- [T0180](https://niccs.cisa.gov/workforce-development/nice-framework) - Perform system administration on specialized cyber defense applications and systems or VPN devices, to include installation, configuration, maintenance, backup, and restoration.
- [T0261](https://niccs.cisa.gov/workforce-development/nice-framework) - Assist in identifying, prioritizing, and coordinating the protection of critical cyber defense infrastructure and key resources.

You can view the [challenge guide](challenge-guide.pdf) here.

Surveillance video indicates that a malicious insider has successfully
concealed a device on the datacenter (management) LAN, with the goal of later
connecting to it from a less privileged network, and using it in subsequent
cyber attacks and for data exfiltration. So far, an `nmap` scan of the
datacenter management network has failed to identify this machine.

Your mission is to locate and establish a network connection to this machine.
You are troubleshooting from a remote location, and are attempting to isolate
this machine without traveling on site and physically searching entire acres
worth of racks in the datacenter.

Rumor has it there are five (that we know of) distinct ways to connect to
this machine, from either the link-local LAN (management network in the data
center), or from one or more router hops away (e.g., from the user network).
The hidden machine may expose different options and behaviors, depending on
how (and from where) a client establishes a connection.

You are given access to a pair of "all-purpose" (`Kali-*`) machines,
connected to the datacenter-management and user networks, respectively.

Once you locate the hidden machine, and successfully establish a connection
to it, you will receive a different flag for each of the five known distinct
methods of establishing a connection.

Example submission:

| Q      | Flag         |
|:-------|:-------------|
| token1 | `8721469a85` |
| token2 | `8767a26255` |
| token3 | `c4a8cbe2b9` |
| token4 | `192916b7da` |
| token5 | `afe07daf4c` |
