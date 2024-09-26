# I Do What I Want!

Reverse engineer a client program's communication protocol and write a script to execute custom behavior on the server.

**NICE Work Roles**

- [Cyber Defense Forensics Analyst](https://niccs.cisa.gov/workforce-development/nice-framework/)
- [Software Developer](https://niccs.cisa.gov/workforce-development/nice-framework/)

**NICE Tasks**

- [T0253](https://niccs.cisa.gov/workforce-development/nice-framework/): Conduct cursory binary analysis.
- [T0288](https://niccs.cisa.gov/workforce-development/nice-framework/): Perform static malware analysis.
- [T0324](https://niccs.cisa.gov/workforce-development/nice-framework/): Direct software programming and development of documentation.

## Background

Analyze an executable using reverse engineering tools. Discover how the executable works and modify it to inject new behavior into communication with the server.

## Getting Started

In the gamespace, navigate to `challenge.us` and download the `client` file.

The encryption key used for client/server communication is a readable ASCII string to make it easier to find.

### Submission Notes

The **first token** is the password sent to the server in the first phase of communication. You will not need to write any code or modify execution for this part.

The **second token** is obtained by sending the string "knock knock" to the server after the login validation is complete.

The **third token** is obtained by sending the string "one more" after a series of arithmetic questions are solved by the client program, and one more is solved..

**All tokens** are printable ASCII hex strings. For example: if the byte sequence `30313233343536373839616263646566` returned by the server corresponds to the hex string `0123456789abcdef`, then submit `0123456789abcdef` as the token.

## Challenge Questions

1. What is the user's password as a string?
2. What did the "knock knock" command return?
3. This question builds on work done for Question 2. What was the result of sending "one more" after the arithmetic queries and then answering one final query?
