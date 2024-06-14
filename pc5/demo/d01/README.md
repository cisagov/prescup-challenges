# Phishing Trip

Analyze and correlate organizational data to identify the insider threat who provided confidential information to a malicious user.

**NICE Work Role**

- [Cyber Defense Forensics Analyst](https://niccs.cisa.gov/workforce-development/nice-framework)

**NICE Tasks**

- [T0027](https://niccs.cisa.gov/workforce-development/nice-framework): Conduct analysis of log files, evidence, and other information to determine best methods for identifying the perpetrator(s) of a network intrusion.

- [T0103](https://niccs.cisa.gov/workforce-development/nice-framework): Examine recovered data for information of relevance to the issue at hand.

## IMPORTANT
This challenge is only partially open sourced. The files in the [challenge directory](./challenge) are provided to give a starting point if you want to recreate the challenge on your own. The full challenge can be completed on the hosted site.

## Background

The IT team at Gringotts Bank believes a malicious outsider gained access to company data through a phishing email. They also think an insider threat might have provided the malicious user with some confidential information. We need your help to identify the individual.

## Getting Started

Note that `challenge.us` inside the gamespace may take a few minutes to load as the challenge environment is prepared.

- Click the `dobby` VM icon to start (username is `user` and password is `tartans` if you are asked to login).
- The Zip file password is case sensitive, but the <u>challenge answers are not case sensitive</u>.
- This challenge uses question-and-answer problems for challenge grading.
- This challenge must be performed sequentially in the order listed below.

## Objectives

**Part 1: Find the password (8 alphanumerical characters) needed to open the Gringotts Documentation Zip files by filtering IRC (Internet Relay Chat) traffic.**

- Log into **dobby** and then click the **Firefox icon** on the dobby desktop toolbar. The browser should open to the `https://challenge.us` Grading Page.

- Download the three challenge artifacts.

- Use Wireshark to filter for IRC messages on the **traffic.pcapng** file. (i.e., type and enter a filter of `irc`). You should see three packets in total.

- Find Ron's password.

  > **Hint:** You can click each packet's Internet Relay Chat listing to see that packet's text comments.

- The Zip file's password is listed in the entry right after Ron's password in the **Password list.md** file.

**Part 2: Determine which email is the phishing email.**

- Open the files in the **Gringotts Documentation.zip** folder with the password used to answer Question 1. Please remember that the Zip password is case sensitive.

  > **Note:** If you enter an incorrect password to open the Zip folder, you will have to close the folder and then re-open it to try again. 

- Carefully read each email to determine which one is the phishing email. Only the number of the email is needed for the answer.

  > **Hint:** Pay attention to the body of each email as well as the `From:`, `To:`, `Sent:`, and `Subject:` fields, and look for any inconsistencies or obvious indicators!

**Part 3: Find the last name of the insider threat.**

- Using the **Access Log.txt** file, determine who was the only user logged on at the time the above email was sent.

**Part 4: Generate a token string after successfully removing the insider threat's account.**

- Click the **shared icon** to log into the shared system (username is `user` and password is `tartans` if you are asked to login).

- Click **Activities**, find the **Add/Remove Users** option, and remove the insider threat's account (username is `user` and password is `tartans` for the Authentication Required window).

- Return to `https://challenge.us` to run the grading check.

  > **Note:** The grading check typically takes 15 or 20 seconds before the results show.

## System Credentials

| system | username | password |
| ------ | -------- | -------- |
| dobby  | user     | tartans  |
| shared | user     | tartans  |

## Note

Attacking or unauthorized access to `challenge.us` (`10.5.5.5` or `64.100.100.102`) is forbidden. You may only use the provided webpage to view challenge progress and download any challenge artifacts that are provided.
