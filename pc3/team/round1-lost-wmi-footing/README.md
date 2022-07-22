# Lost WMI Footing

Gain elevated privileges on a target by utilizing persistence mechanisms that were left behind by another attacker.


**NICE Work Roles:**

- [Cyber Defense Forensics Analyst](https://niccs.cisa.gov/workforce-development/nice-framework/workroles?name=Cyber+Defense+Forensics+Analyst&id=All)

- [Exploitation Analyst](https://niccs.cisa.gov/workforce-development/nice-framework/workroles?name=Exploitation+Analyst&id=All)

    
**NICE Tasks:**  

- [T0432](https://niccs.cisa.gov/workforce-development/nice-framework/tasks?id=T0432&description=All) : Collect and analyze intrusion artifacts (e.g., source code, malware, and system configuration) and use discovered data to enable mitigation of potential cyber defense incidents within the enterprise.

- [T0572](https://niccs.cisa.gov/workforce-development/nice-framework/tasks?id=T0572&description=All) : Apply cyber collection, environment preparation and engagement expertise to enable new exploitation and/or continued collection operations, or in support of customer requirements.

## Note

This challenge guide, aside from this note, is unmodified from the competition version. The challenge relies on a particular system configuration in order to function, and could not be made public. However, the competitor directly interacted with an open-source example script for Impacket called [wmiquery.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/wmiquery.py). The full version of this challenge can be played on the hosted site. 

## Background

Someone has lost their elevated shell on a compromised machine. Luckily, they have set WMI persistence using the event of a failed login. Only problem: we don't know the port to use for the listener or the user name used to trigger the event. We do have the credentials of the compromised machine.

In order to get the information, we left over an Impacket script to query WMI objects. We also used powershell-empire in order to gain persistence. Please use this with the credentials of the administrator on the Windows machine to the information to receive all points for this challenge.

## Getting Started

All of the machines are on 10.5.5.0/24. A quick scan will find the compromised machine on the network. Use the provided credentials to query WMI and find information to regain access to the Windows machine through leftover persistence.

## Submission Format

There are four different submission tokens for this exercise:

- Port number of powershell-empire listener
- Username used to activate WMI event
- Subscription name of the WMI event
- Token located on the User desktop

Find these tokens and submit them as the answer to the relevant questions.

  ## System Credentials

  | System      | Username | Password |
  | -------------- | -------- | -------- |
  | Windows_Machine       | user | scotty@@1  |
  | Kali_Machine   |  user  | tartans |
