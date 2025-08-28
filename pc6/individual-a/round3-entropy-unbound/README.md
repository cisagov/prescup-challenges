# Entropy Unbound

⚔️ **Please wait five minutes before starting the challenge**

💻 Network Analysts have been observing strange DNS traffic on the internal network. It appears that the malware (codenamed AURORA) is using a domain generation algorithm to connect to Nautilus C2 servers.

**NICE Work Roles**
* Digital Forensics
* Exploitation Analysis

For more information on these roles, please visit: https://niccs.cisa.gov/workforce-development/nice-framework

**NICE Tasks**
* [T0167](https://niccs.cisa.gov/workforce-development/nice-framework/): Perform file signature analysis
* [T0179](https://niccs.cisa.gov/workforce-development/nice-framework/): Perform static media analysis
* [T1103](https://niccs.cisa.gov/workforce-development/nice-framework/): Analyze intrusions
* [T1118](https://niccs.cisa.gov/workforce-development/nice-framework/): Identify vulnerabilities
* [T1370](https://niccs.cisa.gov/workforce-development/nice-framework/): Collect intrusion artifact

## Background

As Forensics experts, we are tasked with disrupting the malware's propagation by writing a classifier which will allow us to find the domain AURORA uses, filter them out and, eventually, shut them down.

## Getting Started

To begin, simply click the `kali` button at the bottom of this document's page (just before the Question section). You will not need to ssh into any other machine to complete this challenge.

1) Once on the `kali` asset, open your web browser and navigate to `https://challenge.us/files` after the wait period (at least five minutes). This will reveal a downloadable zip called `entropy_unbound_files.zip`. 

2) Next, download and extract the two files in the .zip. A description of the files can be found below:

```text
└── .zip/
  ├── known_domains.txt <- This is the list of domains that are known to have been created by the domain generation algorithm
  └── test_domains.txt <- This is the list of domains that you will be classifying
```

## Tasking
Write a script that will identify each domain in the `test_domains.txt` file and determine if the domain is malicious (i.e. created by the domain generation algorithm). Your script should generate a file where each row contains a domain, followed by a `,` and then a `1` to classify the domain as malicious or a `0` to classify the domain as safe. 

e.g.

```text
safe.domain.com,1
malicious.domain.com,0
```

Please note that there is only one task in this challenge however, your overall progress will determine which tokens you receive by the end of the competition.

## Submission

**IMPORTANT**
Your answers **must** be placed in `/home/user/data/answers.txt` for grading. Any modifications to the naming or file permissions of this file will disable grading.

Grading will be conducted by the `grading server` located at `https://challenge.us`.

Clicking the "Grade" button will kick off a series of checks to award tokens at pre-determined checkpoints.

Once the server has examined your environment, it will determine the accuracy of your filters and award (or not award) tokens that can be submitted for points in the `Questions` section located under the `Gamespace Resources` section on this challenge page. 

The accuracy requirements for each token can be found below:
* Bronze: 50% accuracy
* Silver: 70% accuracy
* Gold: 85% accuracy
* Master Token: 100% accuracy

## System and Tool Credentials

|system | operating system | username|password| ip |
|-----------|--------|--------|--------|--------|
|kali | Debian |user |tartans| 10.5.5.10 |

## Note

Attacking or unauthorized access to `challenge.us` (10.5.5.5) is forbidden. You may only use the provided web page to view challenge progress and download any challenge artifacts that are provided.

**Be sure that you follow proper data handling procedures so that you do not lose the original copy of the data files.**

## Troubleshooting

**502 Bad Gateway Error**  
If you receive this message, the challenge has not yet been deployed (under five minutes from the launch time)

![502 Bad Gateway Error](img/502%20error.png)

Please be patient and the server will load the challenge shortly.

