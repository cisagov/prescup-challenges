# 911 Call Center Solution

## Server(s)

The 911 call center is based on a VoIP daemon named `pc2voip911d`, running on
Linux (Ubuntu 20) server(s) hosted on the `svc` (data center/service) network,
`192.168.101.0/24`.

On each server, the daemon's binary executable program is available as
`/usr/sbin/pc2voip911d`, and is started as a systemd service via the
`/lib/systemd/system/pc2voip911d.service` unit file. Finally, on each
server instance, the daemon is started with a specific key located in
`/etc/default/pc2voip911d`.

The daemon listens for incoming connections on TCP port 10116, expecting
32-character request strings, and producing a 32-character string in response.

Port forwarding is configured on the firewall/router appliance, mapping
external ports (10116+X) for each server X (where X = 1, 2, ...). In other
words, the externally exposed port for server 1 is 10117. Server 2 will
be reachable on port 10118, etc.

## Workstation(s)

Call center workers use a number of Linux (Ubuntu 20) workstations hosted on
the `usr` network, `192.186.202.0/24`. Due to recent COVID-19 related WFH
policies, workers have been granted permission to log in to the workstation(s)
remotely, using SSH. Public-key based SSH access is available for users to perform
administrative and maintenance activities on the server(s).

## Threat actors and vulnerabilities

Contestants are provided with 2 primary sources of intelligence within the
gamespace:

1. A collection of intelligence documents contained within a folder on the
   desktop of the incident responder laptops.
2. A help desk ticketing system on the "logbook".

The intelligence documents contain a threat profile of a nation-state
sponsored attacker group, along with of reports of malicious cyber activity
which has been attributed to this group. These documents describe their
methods of attack and motives for attacking certain targets. Contestants
should pay attention to the following documents:

* CISA Alert PC20-050A - This is a simulated CISA Alert describing a targeted
  attack on Emergency Services sector of critical infrastructure. It contains
  a cyber kill chain analysis of the attack, along with other indicators. The
  most valuable piece of information is a suggested network IDS signature,
  which could be used to implement an iptables firewall rule to mitigate the
  DoS attack as described in the **solution** section of this guide.
* Vulnerability Note VU#123 - This is a CERT vulnerability note which
  summarizes the 'deadbeef' vulnerability found in the 911 software. This
  should further reinforce the idea that packets containing a payload which
  begins with the string 'deadbeef' should be discarded.
* Threat actor profile - This document mentions coercion and monetary gain as
  motivation. It mentions that the threat actor targets the emergency sector
  and also calls attention to the tools and techniques used in their cyber
  campaigns.
* Intel Report #20190929_025248 - Mentions a brute-force password cracking
  attack over SSH using Hydra, and the use of CoinTicker malware once access
  was gained.
* Intel Report #20200505_074048 - Identifies a person of interest, Mr. Jack
  Bogen, who maybe affiliated with the threat actor group. This report mentions
  his attempt to purchase a luxury automobile using cryptocurrency as well as
  his social media screen name of "ElesaElectric", which he frequently uses to
  brag about the major purchases he makes. These social media posts coincide
  with the dates that  high-profile cyber attacks have taken place.

The remainder of the intelligence documents are mainly chaff, however they
do show a repeating pattern of cyber attacks for this threat actor.

The help desk ticketing system contains 15 tickets, some of which are actively
being worked on by IT and others which have been resolved and closed.
Instructions for accessing the ticketing system are found in a text file on
the desktop of the logbook VM. Contestants should login to the system and
review all of the tickets contained therein. Some tickets are artifacts of
normal IT operations (users asking questions, printer problems, etc.) but
the following are relevant to the vulnerabilities in the challenge environment:

* Ticket #712410 (closed) - Alludes to the fact that there's no longer an
  account lockout policy configured for repeatedly entering the wrong password
  for a user's account. This should hint that the computers are vulnerable to
  password cracking attacks.
* Ticket #832571 (closed) - A 911 dispatcher complaining about lack of remote
  access, and system administrator setting up port-forwarding to enable same.
  Comments in this ticket also demonstrate the system administrator's lack of
  understanding regarding the ports/protocols/services in-use by the 911 system.
* Ticket #154025 (open/answered) - A 911 dispatcher reporting intermittent
  system outages. System administrator responds by stating that he restarted
  the service, but also expresses a lack of understanding of the software, and
  frustration that they no longer have active vendor support. From this, it
  can be inferred that the software is likely vulnerable to the DoS attack
  described in the vulnerability report, and that patching the software would
  not be a likely course of action.
* Ticket #728523 (open/answered) - 911 dispatcher reports receiving a
  threatening email message. The body of the message is contained within the
  ticket. It is an extortion email which demands payment in the form of
  Bitcoin or else the call center's computer systems will be shut down. The
  author of the threatening email also states that they know they have
  targeted a 911 call center and have already gained access to the computer
  systems. The typos and poor wording are intentional to imply that English
  may not be the author's primary language. This should provide a clear call
  to action for contestants to review vulnerabilities and methods of remote
  access contained within the gamespace environment, and to mitigate them in
  the best possible way.

## Solution

Based on social media chatter, activity observed and logged by 911 call center
workers in the logbook ticketing system, and after reviewing intelligence
documents and vulnerability notes found on the "laptop" , two attack vectors
should be considered with utmost urgency:

1. Remotely triggered DoS vulnerability in the `pc2voip911d` daemon, which
   is the main service that must be kept up and running at any time, and

2. Weak passwords on one or more workstation user accounts (open for
   off-site remote access via SSH, due to a new COVID related WFH policy).

Both of these attack vectors must be addressed to protect the service from
being brought down by the miscreants.

## 1. Protecting against the remotely triggered `deadbeef` DoS attack

Vulnerability Report VU#123, contained in the intelligence documents, indicates
that a remotely triggered DoS vulnerability was found in the `pc2voip911d`
software. By sending a request string with the first 8 characters set to
`deadbeef`, an attacker can cause the daemon to stop responding to subsequent
requests until manually restarted (e.g., via `systemctl restart pc2voip911d`).
Contestants are tipped off about restarting the service in Help Desk Ticket
#154025.

To prevent this vulnerability from being triggered, a packet filtering rule
must be added that discards requests sent to any of the servers when the first
8 characters of the request string match `deadbeef`. A hint for developing
this rule is found in the intelligence document titled "CISA Alert PC20-050A".
Specifically contestants should pay attention to the suggested network IDS rule
found in that document, which should be transformed into a firewall rule.
The best place for such a rule is each server, using `iptables`. The following
rule discards "bad" requests while quickly allowing the server to resume
addressing valid clients:

```
iptables -I INPUT -p tcp --dport 10116 \
	-m string --to 52 --algo bm --string 'deadbeef' \
	-j REJECT --reject-with tcp-reset
```

Given that the TCP header ends 44 bytes into the packet, the first 8 bytes
of the TCP payload end at the 52 byte mark. This rule ensures that only
requests matching `deadbeef` at the ***start*** of the request are discarded,
minimizing disruption of *valid* requests (which *may* contain `deadbeef`
anywhere else in the request string, other than the very beginning).

Using a local rule on each server also prevents against malicious insiders
launching attacks from e.g. one of the workstations!

## 2. Protecting against remote compromise via SSH

Based on the information contained in Intel Report #20190929_025248 and
Help Desk Ticket #712410 , there is a high chance that attackers have been
attempting to guess call center workers' SSH passwords (e.g., by using `hydra`
to try many different user/password combinations. This can be corroborated by
examining `/var/log/auth.log*` entries on each workstation -- looking there
will provide ample evidence of recent SSH brute-force activity.

Kali laptops contain `users.txt` and `passwords.txt` files for pen-testing use
with `hydra`. After entering each workstation's IP address in a `targets.txt`
file, we can launch our own brute-force password guessing `hydra` attack:

```
hydra -L users.txt -P passwords.txt -M targets.txt -v ssh
```

After a while (5-10 minutes), we should be able to obtain at least one
vulnerable username/password combination available on a workstation.

Looking through each user's `~/.ssh/` directory, we see a `known_hosts` file
containing the servers' public key(s), and an `id_rsa[.pub]` key pair. On the
server's root account, there will be a `~/.ssh/authorized_keys` file, listing
the public keys of users authorized to log in as root, remotely, from their
workstations, in order to perform administrative and maintenance tasks.

This means that if any user account was compromised by an external attacker,
it can be used to gain full root access to the server, with all the implied
consequences (e.g., complete destruction of the server, in particular the
shutdown and removal of `pc2voip911d`, resulting in a total loss of service).

Since users must be allowed to continue logging in from home, an acceptable
solution to this attack vector would be to:

1. force a password change for each user, and

2. remove key-based root access to the server. Preferably, unprivileged
   accounts with strong passwords should be created on the server, and
   granted `sudo` ability to conduct any necessary tasks.

For a successful solve of this challenge, password change(s) and/or removal
of key based root access to the server(s) from any workstation should be
sufficient.
