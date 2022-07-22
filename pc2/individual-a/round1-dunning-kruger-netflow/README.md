# Dunning & Kruger Netflow Inc.

Given a set of collected Netflow records, players must identify the nature
of the events that occurred, and generate a timeline analysis thereof.

**NICE Work Roles:**

- [Network Operations Specialist](https://niccs.cisa.gov/workforce-development/nice-framework/workroles?name=Network%20Operations%20Specialist)
- [Cyber Defense Incident Responder](https://niccs.cisa.gov/workforce-development/nice-framework/workroles?name=Cyber%20Defense%20Incident%20Responder)

**NICE Tasks:**

- [T0160](https://niccs.cisa.gov/workforce-development/nice-framework/tasks?id=T0160&description=All) - Patch network vulnerabilities to ensure that information is safeguarded against outside parties.
- [T0161](https://niccs.cisa.gov/workforce-development/nice-framework/tasks?id=T0161&description=All) - Perform analysis of log files from a variety of sources to identify possible threats to network security.

## Background

In light of the recent push to allow remote work, Dunning & Kruger, Inc. has
allocated a publicly routable IP network to their user workstations, and has
enabled remote SSH access since the majority of employees are now connecting
from home. The user LAN has been allocated addresses within 168.192.0.0/24.

D&K also allocates non-routable (RFC1918) space for its datacenter machines,
in the 192.168.0.0/24 range.

The network is monitored via IDS, and netflow records are collected to
support incident response activities, whenever necessary.

An IDS alert was received indicating a possible unauthorized access to one
of the database servers connected to the D&K datacenter network.

One of D&K's database administrators is known to have legitimately accessed
the same server during roughly the same time window.

So far, it has been established that the attacker ran a ping scan of the user
network, followed by a Hydra SSH brute-force attack against any machines that
responded to pings. Once successfully compromised, a user workstation was
used to access a database server on the internal datacenter network.

You are presented with an nfcapd file representing NetFlow records saved
during the time frame of the possible incident, and are tasked with
conducting an initial assessment of the situation.

## Getting Started

The provided .iso file represents a CD/DVD drive image containing
an nfcapd file with Netflow data collected from D&K's router. Familiarize
yourself with the `nfdump` command line tool (using any other Netflow
analysis tool is allowed).

Finally, please note that, internally, Netflow records in an `nfcapd` file
use UTC timestamps, but that the `nfdump` utility automatically converts
them to ***local*** time (as configured on the underlying machine) during
output. You are expected to provide timestamps in `US/Eastern` format.

On Linux, you can confirm this by issuing the `timedatectl` command. To set
the appropriate time zone, run:

  ```
  sudo timedatectl set-timezone 'US/Eastern'
  ```

## For credit, answer the following questions:

1. What is the attackers' (external) IP address?
2. What is the legitimate administrator's (external) IP address?
3. What is the IP (on the datacenter network) and port number of the D&K
   database server?
4. When does the Hydra SSH brute-force attack (incl. initial SYN scans of
   tcp/22) start and end?
5. What is the duration of the longest successful TCP attacker-initiated
   session between the compromised D&K user-LAN IP and the D&K datacenter
   machine?

Example Answer:

| Q | A                           |
|---|-----------------------------|
| 1 | `192.168.148.23`            |
| 2 | `192.168.148.24`            |
| 3 | `192.168.148.26:8080`       |
| 4 | `11:30:45.012,12:01:20.789` |
| 5 | `44.345`                    |
