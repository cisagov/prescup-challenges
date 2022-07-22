# Who stole my Flask?

You have been hired as a penetration tester for a new company. They have been building out a site for their business and want to know if it has any vulnerabilities. 

**NICE Work Roles**
- [Exploitation Analyst](https://niccs.cisa.gov/workforce-development/nice-framework/workroles?name=Exploitation%20Analyst&id=All&fwid=All&name_selective=Exploitation%20Analyst)
- [Vulnerability Assessment Analyst](https://niccs.cisa.gov/workforce-development/nice-framework/workroles?name=Vulnerability%20Assessment%20Analyst&id=All&fwid=All&name_selective=Vulnerability%20Assessment%20Analyst)

**NICE Tasks**

- [T0028](https://niccs.cisa.gov/workforce-development/nice-framework/tasks?id=T0028&description=All) - Conduct and/or support authorized penetration testing on enterprise network assets.
- [T0266](https://niccs.cisa.gov/workforce-development/nice-framework/tasks?id=T0266&description=All) - Perform penetration testing as required for new or updated applications.
- [T0641](https://niccs.cisa.gov/workforce-development/nice-framework/tasks?id=T0641&description=All) - Create comprehensive exploitation strategies that identify exploitable technical or operational vulnerabilities.
- [T0736](https://niccs.cisa.gov/workforce-development/nice-framework/tasks?id=T0736&description=All) - Lead or enable exploitation operations in support of organization objectives and target requirements.

## Background

A new company, J Mori's, has been working on creating a site that is meant to rival other social media platforms. They have built and released a beta site to select people who applied and got approved.

The site has most basic functionality completed, but they're still working on implementing many other aspects to enhance the experience. In the meantime, the beta site is where they are also recording feedback and monitoring users.

You have been hired to test the beta site's functionality and see if you can find any vulnerabilities that will allow you to gain access to higher privilege accounts. If so, can you leverage those accounts to then gain access to files on the machine the site is being hosted on?

## Getting Started

You will need to start the server, which requires a Python 3.6+ installation to run. Once Python is installed, you should be able to start the server by running the following commands:
```
cd server
python3 -m pip install -r requirements.txt
python3 main.py
```
If you get the message that the server is running on a local address on port 5000, then it worked. Leave the server running in a terminal in the background while working on the challenge.
The server URL is `http://localhost:5000`.

## Submission Format

There are three (3) submission parts for this challenge. They are

1. Hex string found on site after elevating account permission above 'user'.
2. Hex string found on site after elevating account permission above 'admin'.
3. Hex string inside of the 'flag.txt' file.
