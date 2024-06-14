# Shadowunboxin

Exploit weaknesses and crack a spaceship's network!

**NICE Work Roles**

- [Exploitation Analyst](https://niccs.cisa.gov/workforce-development/nice-framework)
- [Vulnerability Assessment Analyst](https://niccs.cisa.gov/workforce-development/nice-framework)

**NICE Tasks**

- [T0028](https://niccs.cisa.gov/workforce-development/nice-framework): Conduct and/or support authorized penetration testing on enterprise network assets.
- [T0570](https://niccs.cisa.gov/workforce-development/nice-framework): Apply and utilize authorized cyber capabilities to enable access to targeted networks.

## IMPORTANT
This challenge is only partially open sourced. The files in the [challenge directory](./challenge) are provided to give a starting point if you want to recreate the challenge on your own. The full challenge can be completed on the hosted site.

## Background

You are tasked with sending a phishing email with a malicious payload to a specific user (`user@merch.codes`) to gain access to their machine. Once inside, you need to find and read two important files, one of them is said to be encrypted. Intelligence reports say the user is known to use weak passwords and reuse passwords. Keep this in mind.

## Getting Started

You have access to a Kali machine on the network (`10.5.5.138`) with access to the mail server (`https://mail.merch.codes`) and the user network. 

This is a two-part challenge. First, send a phishing email to obtain access to the `user` machine where you will find and read the first file and obtain the first token. Second, once inside the machine, you will find and decrypt the second file and obtain the second token.

**The mail application server in the environment might require a few minutes to fully start up. Please be patient!**

## Phishing Required Parameters

Due to the mechanics of this challenge, sending the phishing email and executing your payload requires some specific conditions to be met. These conditions are:

1. Browse to `https://mail.merch.codes` and login with the `customer@merch.codes` credentials provided below.
2. Prepare a phishing email to `user@merch.codes` with these parameters:
   - A URL in the **Message** field that points to `http://order15887.pdf`, but has the text of `order15887.pdf`. This implies you are sending something important, but it is actually a link.
   - The **Subject:** and other fields can be whatever you like.

>**Note:** Internal DNS has been pre-configured to map `http://order15887.pdf` to your local IP (`10.5.5.138`) for you.

The target is a **Linux x86_64** system.

After you draft and send the email, ensure you host your malicious payload locally. We have provided an example Python webserver template that downloads the payload automatically once someone visits `http://order15887.pdf`. You can find that file here: `https://challenge.us/files`. 

## Tips

Send the email after you have drafted it. This guarantees that it has time to reach the email server before any grading checks are made.

For the second part, we provided you with the wordlist needed. Download `wordlist.txt` at `https://challenge.us/files`.

## Submissions

When the email has been sent, and the necessary files and configurations are in place to gain a reverse shell, go to `https://challenge.us` and click `Grade`. This triggers actions on the target system. 

If you have configured everything correctly, the webpage will remain on `Your challenge is being graded`, and you will receive a reverse shell. If you have not, the webpage will update and provide you with reason(s) for failure.

## System and Tool Credentials

|system/tool|username|password|
|-----------|--------|--------|
| Kali | user | tartans |
| https://mail.merch.codes | customer@merch.codes | tartans |

## Note

Attacking or unauthorized access to `challenge.us` (10.5.5.5) is forbidden. You may only use the provided web page to view challenge progress and download any challenge artifacts that are provided.

## Challenge Questions

1. What is the value found inside token1.txt on the target machine? (`/home/user/token1.txt`)
2. What is the value found inside token2.txt.gpg on the target machine?
3. What is the password of the user 'admin'?
