# Finding the HOIC

Help prevent a cyber attack. Gather account and website intel from a known malicious forum, use it to locate and log into the site. Find the High Orbit Ion Canon (HOIC) tool and use it to predict the actor's next move.

**NICE Work Roles**

- [Exploitation Analyst](https://niccs.cisa.gov/workforce-development/nice-framework/)
- [Cyber Operations](https://niccs.cisa.gov/workforce-development/nice-framework/)

**NICE Tasks**
- [T0028](https://niccs.cisa.gov/workforce-development/nice-framework/): Conduct and/or support authorized penetration testing on enterprise network assets.
- [T0570](https://niccs.cisa.gov/workforce-development/nice-framework/): Apply and utilize authorized cyber capabilities to enable access to targeted networks.
- [T0591](https://niccs.cisa.gov/workforce-development/nice-framework/): Perform analysis for target infrastructure exploitation activities.

## Background

Use the provided Kali machine to explore and exploit websites; gather data about accounts on the malicious actor's website and the HOIC software.

## Getting Started

Log in to the `kali` VM, browse to `http://123.45.67.100` and begin gathering profile data from the forums. Use the forums to find websites and email addresses that may prove useful. Use the provided `passwords.txt` and `wordlist.txt` attached to your Kali VM (mounted to the CDROM on the desktop) and your offensive skills to find the HOIC software.

## Submissions

There are five (5) tokens to retrieve in this challenge. Here are some additional details about each token.

- **Token 1:** Scan the website located at `http://123.45.67.100`. Build a list of websites and email addresses. Find the domain of the active HOIC web site.
- **Token  2:** Use the email addresses you discovered, along with the provided password list, to access the HOIC website. Which email address was used to successfully log in?
- **Token 3:** Find the **HOIC.zip** file on the HOIC website from Token 1. What is the password used to open the zip archive?
- **Token 4:** Find the domain that the HOIC software tries to contact.
- **Token 5:** What is the value of the `ClientId` the malicious HOIC tool attempts to transmit back to the command and control server?

## Challenge Questions

1. What is the domain of the HOIC web site?
2. What email address did you use to login to the HOIC web site?
3. Find the HOIC.zip file on HOIC web site that you found in question #1. What password was used to decrypt the HOIC.zip archive?
4. What domain does the HOIC software try to contact?
5. What is the value of the ClientId that the malicious HOIC tool attempts to transmit back to the command and control server?
