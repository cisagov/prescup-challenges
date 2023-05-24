# Who Called the Doc?

Your cybersecurity department has been notified that credentials for your employees have recently been found in a repository on a popular file sharing site. Though it does not consist of all user credentials in the environment, the attacker indicates that more credentials will be for sale along with shell access to assets within your network. You will need to determine what payload was used to compromise the network, create them in your lab then analyze the malware to identify and scan assets to find where the attacker has another payload staged.

**NICE Work Role:**

- [Cyber Defense Incident Responder](https://niccs.cisa.gov/workforce-development/nice-framework)

**NICE Tasks:**

- [T0278](https://niccs.cisa.gov/workforce-development/nice-framework) and use discovered data to enable mitigation of potential cyber defense incidents within the enterprise.

- [T0175](https://niccs.cisa.gov/workforce-development/nice-framework).

- [T0163](https://niccs.cisa.gov/workforce-development/nice-framework) - Perform cyber defense incident triage, to include determining scope, urgency, and potential impact, identifying the specific vulnerability, and making recommendations that enable expeditious remediation.

## IMPORTANT

There are no downloadable artifacts provided for the challenge. The full challenge can be completed on the hosted site.

## Background

As an incident responder, you will need to determine what payload was used in the attack on the network. Using your Kali machine you will need to recreate samples of the payload based on the provided intel, then analyze those samples using forensic tools. Once analysis is complete, you will need to find staged copies of the malware within the network using YARA scans. Fortunately, your organization has installed YARA (yara64.exe) on workstations and enabled RDP (using domain admin creds) in preparation for your scanning activity, therefore scans can be run locally on each machine.

Intelligence agencies indicate that this specific attacker has targeted user directories on Windows 10 workstations within other organizations using an exploit for the following vulnerability.

| CVE                                                                | Severity                         |
|--------------------------------------------------------------------|----------------------------------|
| [CVE-2018-10583](https://nvd.nist.gov/vuln/detail/CVE-2018-10583)  | 7.3                              |

## Getting Started

Utilize your lab workstation to create a sample exploit based on the available intelligence. Using that payload sample you will need to perform analysis in order to create meaningful Yara rules. With the rules created, you must use Yara's scanning engine to scan for copies of the malware on machines where it has been staged. Once the staged payload is located, obtain the MD5 hash value for it along with the IP addresses that it is pointing to and submit them to complete this challenge. Keep in mind that opening the payload on the local machine may be blocked by AV, so alternative methods to open the file and analyze code will be required.

You can view the [challenge guide](challenge-guide.pdf) here.

## Submission Format

Submission format is as follows:

Part 1 of 2:  Payload Hash Value
```
1234abcd58a66530c95d257f811977ba
```
Part 2 of 2:  Payload IP Address
```
10.10.10.10
```

