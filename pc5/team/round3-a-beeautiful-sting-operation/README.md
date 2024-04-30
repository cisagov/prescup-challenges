# A Beeautiful Sting Operation

Using a deployed T-Pot honeypot, investigate log and IDS data to identify threats and threat actors by their activities, techniques, tactics, procedures, and indicators of compromise.

**NICE Work Roles**

- [Cyber Defense Analyst](https://niccs.cisa.gov/workforce-development/nice-framework)
- [Cyber Defense Incident Responder](https://niccs.cisa.gov/workforce-development/nice-framework)

**NICE Tasks**
- [T0161](https://niccs.cisa.gov/workforce-development/nice-framework): Perform analysis of log files from a variety of sources (e.g., individual host logs, network traffic logs, firewall logs, and intrusion detection system [IDS] logs) to identify possible threats to network security.
- [T0258](https://niccs.cisa.gov/workforce-development/nice-framework): Provide timely detection, identification, and alerting of possible attacks/intrusions, anomalous activities, and misuse activities and distinguish these incidents and events from benign activities.
- [T0290](https://niccs.cisa.gov/workforce-development/nice-framework): Determine tactics, techniques, and procedures (TTPs) for intrusion sets.
- [T0294](https://niccs.cisa.gov/workforce-development/nice-framework): Conduct research, analysis, and correlation across a wide variety of all source data sets (indications and warnings).


## Background

Our security team has deployed a honeypot in the DMZ to attract potential threats into making themselves known. The honeypot was built using the latest version of [T-Pot](https://github.com/telekom-security/tpotce) as of December 1, 2023. The system has an internal address of `10.7.7.200`. All external traffic is port-forwarded through the WAN interface of the firewall at `123.45.67.89`.

Your team must analyze past and new Kibana logs to identify threat actors based on observed events and other provided datasets and threat information.

Notable honeypot dashboards include: Cowrie, Dionaea, Mailoney, and Suricata.

## Getting Started

Kibana is your main source for information because it includes several honeypot-based dashboards. You have access to the T-Pot Web GUI tools at `https://10.7.7.200:64297` from any in-game Buzz/Kali system using the `web-user|tartans` credentials. Data logs for each honeypot are located at `/data/[honeypot or service name]/log/` on the T-Pot system. Copies of the necessary log files have also been copied to the `/home/tsec/` directory on T-Pot.

You also have access to a single external VM for testing named "Murder Hornet." This system is placed on the other side of an ISP router to your WAN. Murder Hornet allows you to pose as the attacker would have posed to verify logs and alerts. An example IP setting of `130.100.100.100/1` with a default gateway of `128.1.1.1` will suffice.

Finally, several pertinent datasets and reports have been made accessible at: `https://challenge.us/files`.

## Investigations

Investigate past logs occurring on past dates as well as ongoing live activities to answer each challenge question. Each question can be researched and answered independently because they don't relate to each other, allowing team members to split up the work. The events of each part occurred on different dates to avoid co-mingling of analysis tasks.

***Note:** Ignore any logs or events tied to `10.5.5.5`(challenge.us) or the internal networks--these are startup logging processes not related to the challenge or normal traffic.*

Any binaries discovered as part of your investigations should be considered safe to run or analyze freely on your Kali workstation.

For each task or question, think about which Kibana dashboards and data logs can help you in your investigation. You may need to expand the bucket size of certain "Top 10" charts within the dashboards to see the full dataset. Task-related documentation can be found at `https://challenge.us/files` . The documentation corresponds with challenge parts numbered below. **Part 4** has two questions to answer.

1. **Part 1:** Which threat actor was responsible for breaching and then attempting to use a set of credentials that is present in your organization via SSH, Telnet, and FTP services on January 11th (UTC), 2024?
2. **Part 2:** Which threat actor was responsible for attempting to login to the fake Cowrie filesystem today (i.e., during the challenge) based on its IP address after correlating  that IP to prior activities on the early hours of December 15th, 2023 (UTC)?
3. **Part 3:** How many email messages received by the open relay on January 12th, 2024, (UTC) match the corresponding threat actor information/attachments found in the phishing report based on the email messages received by the relay today (i.e., during the challenge)?
4. **Part 4: a.)** How many unique Suricata alert signature IDs are generated from an all-inclusive enum4linux scan (e.g. enum4linux -a 123.45.67.89)?

    **Part 4: b.)** How many total Suricata log events (not unique types) match the Suricata alert signature IDs attributed to scans used by the threat actor in the scan report based on the activities observed on January 10th, 2023? Your answer should be in the hundreds.

## System Tools and Credentials

| system | OS type | username | password |
|--------|---------|----------|--------|
| Buzz | Kali | user | tartans|
| T-Pot (OS) | Debian | tsec | tartans |
| T-Pot web tools |  `https://10.7.7.200:64297/` | web-user | tartans |

## Note

Attacking or unauthorized access to `challenge.us` (`10.5.5.5` or `64.100.100.102`) is forbidden. You may only use the provided webpage to view challenge progress and download any challenge artifacts that are provided.

## Challenge Questions

1. Which threat actor was responsible for breaching and then attempting to use a set of credentials that is present in your organization via SSH, Telnet, and FTP services on January 11th (UTC), 2024?
2. Which threat actor was responsible for attempting to login to the fake Cowrie filesystem today (i.e., during the challenge) based on its IP address after correlating that IP to prior activities on the early hours of December 15th, 2023, (UTC)?
3. How many email messages received by the open relay on January 12th, 2024, (UTC) match the corresponding threat actor information found in the phishing reports based on the email messages received by the relay today (i.e., during the challenge)? Your answer should be on the order of tens of messages.
4. How many unique Suricata alert signature IDs are generated from an all-inclusive enum4linux scan (e.g., enum4linux -a 123.45.67.89)?
5. How many total Suricata log events (not unique types) match the Suricata alert signature IDs attributed to scans used by the threat actor in the scan report based on the activities observed on January 10th, 2024? Your answer should be on the order of hundreds of alerts.
