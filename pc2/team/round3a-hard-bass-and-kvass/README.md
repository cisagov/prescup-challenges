# Hard Bass & Kvass

Recover an exfiltrated file from captured network traffic.

**NICE Work Roles:**
- [Cyber Defense Forensics Analyst](https://niccs.cisa.gov/workforce-development/nice-framework)

**NICE Tasks:**

- [T0035](https://niccs.cisa.gov/workforce-development/nice-framework).
- [T0532](https://niccs.cisa.gov/workforce-development/nice-framework) for recovery of potentially relevant information.

Babushka's Kvass and East-European Delicacies is suspected of running a Troll
Farm operation on the side. An undercover operative has infiltrated the team,
with the goal of finding the credentials to the server controlling the large
number of sock-puppet social media accounts. Recently, the undercover agent
has stopped checking in with their handler, and appears to have gone missing.

The last report suggests that the agent managed to find the account name and
password to the sock-puppet C&C server, and was looking for ways to exfiltrate
that information in a way that would not be blocked or detected by Babushka's
network defense (firewall and IDS) systems, which block most outbound ports,
and respectively, perform session reassembly and deep packet inspection on tcp
and udp sessions allowed through the firewall.

Standard protocol indicates that the agent would attempt to embed the admin
password into an otherwise innocuous looking file (such as a recipe), and
attempt to find some sort of side channel around network restrictions and
defense measures.

A fragment of Babushka's border-router traffic was acquired from their upstream
ISP (see file [kvass.pcap](challenge/kvass.pcap)), shortly before the undercover agent was expected
to check in with their handler. However, attempts at identifying the presence
of any exfiltrated data have so far been unsuccessful.

Your mission, should you choose to accept it, is to analyze the captured
traffic, isolate the exfiltrated file, and extract the social media sock-puppet
C&C admin password -- on the assumption that our undercover agent has
ultimately managed to successfully exfiltrate it before going dark. Just to be
100% sure, please also include the `md5sum` (md5 hash) of the extracted
exfiltrated file.

Example solution:

|    Q     |    Flag:                           |
|----------|------------------------------------|
| password | `864837b4982abc5e7f2d436ee63fa9ea` |
|  md5sum  | `2265ff07d358670e71b0865285869b45` |
