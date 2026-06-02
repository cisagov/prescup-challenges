# Daemon Hunter

A remote machine is running a daemon that has an open service. Gather any information you can find.

**NICE Work Roles**

- [Cyber Defense Analyst](https://niccs.cisa.gov/tools/nice-framework/)
- [Exploitation Analyst](https://niccs.cisa.gov/tools/nice-framework/)

**NICE Tasks**

- [T0028](https://niccs.cisa.gov/tools/nice-framework/): Conduct and/or support authorized penetration testing on enterprise network assets.
- [T0566](https://niccs.cisa.gov/tools/nice-framework/): Analyze internal operational architecture, tools, and procedures for ways to improve performance.


## Background

A remote machine `vault` is running a service. You need to run tests and checks against the service and try to find as much information as you can from the service. You need to:

1. Find the public token.
1. Recover an encrypted token.
1. Recover the runtime token.
1. Decrypt the secret-file token.

Your sources say that the following keywords are significant:

- GETPUB
- PEEKFILE
- INFO
- UPLOAD
- CALL

Known files on the target are:
- secret_parts.h
- symbols.txt
- token_secret_file.enc

## Getting Started

You are provided access to the standard Kali machine. The service accepts very specific and short commands.


## System and Tool Credentials

|system/tool|username|password|
|-----------|--------|--------|
|kali|user|password|
|vault|||
