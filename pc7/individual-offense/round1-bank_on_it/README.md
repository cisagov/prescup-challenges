# Bank On It

The Trustfall Bank is committing various crimes and financial fraud, and you've been tasked with taking them down. Your mission is to investigate and infiltrate their website in order to bring them to justice.

**NICE Work Roles**

- [Vulnerability Analysis](https://niccs.cisa.gov/tools/nice-framework)
- [Exploitation Analysis](https://niccs.cisa.gov/tools/nice-framework)

**NICE Tasks**

- [T1359](https://niccs.cisa.gov/tools/nice-framework): Perform penetration testing.
- [T1118](https://niccs.cisa.gov/tools/nice-framework): Identify vulnerabilities.

## Background

The Trustfall Bank, located overseas, has been committing insider trading and identity theft. As the Agency's most talented agent, you've been given the go-ahead to bring them down. The agency has given you a list of tasks to complete to verify that you have successfully infiltrated their systems. These include extracting the source code for potential future operations and manipulating existing accounts to cause mayhem.

## Getting Started

Using the provided Kali machine, visit `http://trustfallbank.us` to begin investigating.

## Tokens

The tokens are formatted as `PCCC{some_words123_here}`.

The tokens may be completed in any order, although extracting the source code first may make the other tasks easier.

Token 4 requires a grading check, which is performed by visiting `http://trustfallbank.us/grade/account-drain`. 

1. The source code has been exposed; find the token in the `config` file where this exposure occurs.
2. Find the token that used to be in the source code.  
3. The token is the account name for one of `bob`'s accounts.
4. Transfer all of `alice`'s funds to `carol`'s investment account. For correct grading, use a single complete transfer for each account. 
    - That is, transfer `$7336.74` from Alice's Checking and `$6820.37` from Alice's savings to Carol's investment account.
5. Break into the admin's current session and find the token. 
    - Note that the admin account is not in the database.

## System and Tool Credentials

|system/tool|username|password|
|-----------|--------|--------|
|kali-VNC|user|password|
