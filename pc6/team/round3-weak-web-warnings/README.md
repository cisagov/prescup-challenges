# WWW (Weak Web Warnings)

A small business developed a simple web server to consolidate their security alerts. Despite being a simple website, it's riddled with vulnerabilities with some not-so-simple caveats. You'll need to be clever to exploit them successfully. Can you find them all?

**NICE Work Roles**

- [Exploitation Analysis](https://niccs.cisa.gov/workforce-development/nice-framework/)
- [Vulnerability Analysis](https://niccs.cisa.gov/workforce-development/nice-framework/)

**NICE Tasks**

- [T1091](https://niccs.cisa.gov/workforce-development/nice-framework/): Perform authorized penetration testing on enterprise network assets.
- [T1118](https://niccs.cisa.gov/workforce-development/nice-framework/): Identify vulnerabilities.


## Background

Use the provided Kali machine to investigate and exploit `web.us`, a simple (and terribly insecure) tracker for security alerts. 

## Getting Started

The `web.us` server only offers two simple features: tracking security alerts and/or events, and listing the hosts and credentials for the business.

## Submission

There are 4 tokens to retrieve in this challenge. Each token is a 12-character hexadecimal value.

- Token 1: Retrieve the token found in a comment in the source code of the website.
- Token 2: Successfully make a request for the `token.php` page; the token will be printed at the top of every page after `token.php` is executed.
- Token 3: Retrieve the token stored in the website's database (table `Token`, column `Token`).
- Token 4: Retrieve the token stored in the application's environment variables.

## System and Tool Credentials

|system/tool|username|password|
|-----------|--------|--------|
|kali-weakweb|user|tartans|

## Note

Attacking or unauthorized access to `challenge.us` (10.5.5.5) is forbidden. You may only use the provided web page to view challenge progress and download any challenge artifacts that are provided.