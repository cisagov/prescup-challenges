# Crazy for PGP

A message from the notorious troublemaker  known as 'The Puzzler' has been decoded: "Riddle me this: I am a key without teeth, yet I unlock doors with ease. You'll need me to open messages that only my counterpart can see. What am I?”

It seems they want you to decode their PGP puzzles. Are you up for the task?

**NICE Work Roles**
- [Vulnerability Analysis](https://niccs.cisa.gov/workforce-development/nice-framework)
- [Cyberspace Operations](https://niccs.cisa.gov/workforce-development/nice-framework)

**NICE Tasks**
- [T1118](https://niccs.cisa.gov/workforce-development/nice-framework): Identify vulnerabilities
- [T1035](https://niccs.cisa.gov/workforce-development/nice-framework): Determine how threat activity groups employ encryption to support their operations


## Background

Use the provided Kali machine to decrypt and encrypt files and messages. 

## Getting Started

Our team has found messages and keys left by 'The Puzzler'. The files can be downloaded at `challenge.us`. The `challenge.us` site may take several minutes to become accessible.

Log in to the Kali VM and begin investigating.

The first challenge involves looking through a number of email messages intercepted by 'The Puzzler'. Download the emails (`part1_messages.tar.gz`) and the public key (`part1_pub_key.asc`) from `challenge.us`. Find out which email was tampered with by using the provided public key. Each email has a hex string at the end of its content. The token is the hex string contained at the end of the tampered email.

Next, 'The Puzzler' wants you to decode an encrypted message that is available from `challenge.us`. Download the message (`part2_encrypted_message.asc`) and keys (`part2_public_command_key.asc` and `part2_user_keys.asc`) from `challenge.us` and decrypt the message. Once decrypted, follow the instructions within the message and use the provided public command key to complete the task. Make sure to follow the guidance in the "Submission" section to ensure proper grading.

Finally, 'The Puzzler' wants you to break an insecure implementation of CBC encryption. There is a `cbc-server` machine at `10.5.5.101` that is hosting a UDP server on port `1337`. It will accept any plaintext payload, encrypt the payload using its encryption key, and then send back the encrypted payload. A snippet of the server's code, including the CBC implementation, can be found at `challenge.us/files/cbc_snippet.py`.

You will need to write your own client to interface with the server and break the insecure implementation of CBC to recover the encryption key.

## Submission

There are 3 tokens to retrieve in this challenge. Tokens 1 & 2 are 12-character hexadecimal values. Token 3 is an 8-character hexadecimal value. The tokens can be retrieved in any order.

Token 2 requires a grading check from `challenge.us`. To ensure proper grading, copy the output from the following command to the box on `challenge.us` (this will create a hex dump of your encrypted message and remove formatting):

 `xxd -p yourencryptedsecretmessage.txt.gpg | tr -d '\n'`

When you encrypt the message, you should **NOT** use ASCII armor. Your encrypted message should be a raw binary. 

## System and Tool Credentials

| system/tool | username | password |
| --- | --- | --- |
| kali-crazy4pgp | user | tartans |


## Note

Attacking or unauthorized access to `challenge.us` (10.5.5.5) is forbidden. You may only use the provided web page to view challenge progress and download any challenge artifacts that are provided.