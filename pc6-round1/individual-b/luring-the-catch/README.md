# Luring the Catch

The fish aren't biting, or maybe you just aren't using the right bait? Examine the Fake Fishing Company's `fakefish.co` website for clues to help you craft a phishing message that will fool an employee into clicking on your false link.

**NICE Work Role**

- [Exploitation Analysis](https://niccs.cisa.gov/workforce-development/nice-framework/)

**NICE Tasks**

- [T1690](https://niccs.cisa.gov/workforce-development/nice-framework/): Identify exploitable technical or operational vulnerabilities
- [T1635](https://niccs.cisa.gov/workforce-development/nice-framework/): Access targeted networks


## Background

The Fake Fish Company provides extensive phishing awareness training to its employees, and they closely examine email hyperlinks. If the destination URL of a hyperlink is not a known `fakefish.co` domain or subdomain, employees will delete the email.

## Getting Started

Within the challenge environment, several resources are available to you:

- **Email provider:** Use `mail.merch.codes`to send your phishing email.
- **Cloud storage provider:** Use the storage provider, `s3.merch.codes`, to host any files you want a user to download.
- **Command line tool:** If you wish to use API commands with the storage provider, download the command line tool from `challenge.us/files`.

Credentials for accessing these resources are provided below.

Once you have sent your phishing email, go to the `challenge.us` site and click the `Grade Challenge` button.  A response tells you if the user clicked your link or deleted your email.

The grading check can be run multiple times, but **only the most recently sent email** will be evaluated. Any payload previously downloaded and executed by the user is **removed** each time the grading check is run.

To answer Question 2, you need to gain access to the user's machine, so make sure you craft your phish and any payload appropriately.

-----

*Environment Note*: It takes **up to five (5) minutes** for website services to fully come online after the challenge is initially launched. You may observe a "502 Bad Gateway" message if you attempt to access the websites before services have fully started. This is expected and should resolve itself after services have started.

## Challenge Questions

1. What is the 8-digit hexadecimal code you received from the grading check (challenge.us) after your phishing email was successfully sent and the link clicked?
2. What is the 8-digit hexadecimal token you found after gaining access to the targeted user's machine?